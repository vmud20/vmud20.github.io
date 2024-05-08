




	



















































































static void write_history(void);


static void wm_window_match_init(bContext *C, ListBase *wmlist)
{
	wmWindowManager *wm;
	wmWindow *win, *active_win;
	
	*wmlist= G.main->wm;
	G.main->wm.first= G.main->wm.last= NULL;
	
	active_win = CTX_wm_window(C);

	
	
	for(wm= wmlist->first; wm; wm= wm->id.next) {
		
		WM_jobs_stop_all(wm);
		
		for(win= wm->windows.first; win; win= win->next) {
		
			CTX_wm_window_set(C, win);	
			WM_event_remove_handlers(C, &win->handlers);
			WM_event_remove_handlers(C, &win->modalhandlers);
			ED_screen_exit(C, win, win->screen);
		}
	}
	
	
	CTX_wm_window_set(C, active_win);

	ED_editors_exit(C);
	
return;	
	if(wm==NULL) return;
	if(G.fileflags & G_FILE_NO_UI) return;
	
	
	for(win= wm->windows.first; win; win= win->next) {
		BLI_strncpy(win->screenname, win->screen->id.name, MAX_ID_NAME);
		if(win!=wm->winactive) {
			BLI_remlink(&G.main->screen, win->screen);
			
		}
	}
}



static void wm_window_match_do(bContext *C, ListBase *oldwmlist)
{
	wmWindowManager *oldwm, *wm;
	wmWindow *oldwin, *win;
	
	
	if(oldwmlist->first==NULL) {
		if(G.main->wm.first); 
		else wm_add_default(C);
	}
	else {
		
		
		
		if(G.main->wm.first==NULL) {
			
			if(!(G.fileflags & G_FILE_NO_UI)) {
				bScreen *screen= CTX_wm_screen(C);

				
				for(wm= oldwmlist->first; wm; wm= wm->id.next) {
					
					for(win= wm->windows.first; win; win= win->next) {
						
						if(screen->winid==0)
							win->screen= screen;
						else  win->screen= ED_screen_duplicate(win, screen);
						
						BLI_strncpy(win->screenname, win->screen->id.name+2, sizeof(win->screenname));
						win->screen->winid= win->winid;
					}
				}
			}
			
			G.main->wm= *oldwmlist;
			
			
			ED_screens_initialize(G.main->wm.first);
		}
		else {
			
			
			oldwm= oldwmlist->first;
			wm= G.main->wm.first;

			
			wm->initialized= 0;
			wm->winactive= NULL;
			
			
			for(win= wm->windows.first; win; win= win->next) {
				for(oldwin= oldwm->windows.first; oldwin; oldwin= oldwin->next) {
					
					if(oldwin->winid == win->winid ) {
						win->ghostwin= oldwin->ghostwin;
						win->active= oldwin->active;
						if(win->active)
							wm->winactive= win;

						if(!G.background) 
							GHOST_SetWindowUserData(win->ghostwin, win);	

						oldwin->ghostwin= NULL;
						
						win->eventstate= oldwin->eventstate;
						oldwin->eventstate= NULL;
						
						
						win->sizex= oldwin->sizex;
						win->sizey= oldwin->sizey;
						win->posx= oldwin->posx;
						win->posy= oldwin->posy;
					}
				}
			}
			wm_close_and_free_all(C, oldwmlist);
		}
	}
}


static void wm_init_userdef(bContext *C)
{
	UI_init_userdef();
	MEM_CacheLimiter_set_maximum(U.memcachelimit * 1024 * 1024);
	sound_init(CTX_data_main(C));

	
	if(U.flag & USER_FILENOUI)	G.fileflags |= G_FILE_NO_UI;
	else						G.fileflags &= ~G_FILE_NO_UI;

	
	
	if((G.f & G_SCRIPT_OVERRIDE_PREF) == 0) {
		if ((U.flag & USER_SCRIPT_AUTOEXEC_DISABLE) == 0) G.f |=  G_SCRIPT_AUTOEXEC;
		else											  G.f &= ~G_SCRIPT_AUTOEXEC;
	}
	if(U.tempdir[0]) BLI_where_is_temp(btempdir, FILE_MAX, 1);
}

void WM_read_file(bContext *C, const char *name, ReportList *reports)
{
	int retval;

	
	errno = 0;

	WM_cursor_wait(1);

	
	
	
	retval= BKE_read_exotic(CTX_data_scene(C), name);
	
	
	if (retval == BKE_READ_EXOTIC_OK_BLEND) {
		int G_f= G.f;
		ListBase wmbase;

		
		
		wm_window_match_init(C, &wmbase); 
		
		retval= BKE_read_file(C, name, reports);
		G.save_over = 1;

		
		if(G.f != G_f) {
			const int flags_keep= (G_SCRIPT_AUTOEXEC | G_SCRIPT_OVERRIDE_PREF);
			G.f= (G.f & ~flags_keep) | (G_f & flags_keep);
		}

		
		wm_window_match_do(C, &wmbase);
		WM_check(C); 
		


		if(retval == BKE_READ_FILE_OK_USERPREFS) wm_init_userdef(C);	
		
		if (retval != BKE_READ_FILE_FAIL) {
			G.relbase_valid = 1;
			if(!G.background) 
				write_history();
		}


		WM_event_add_notifier(C, NC_WM|ND_FILEREAD, NULL);


		CTX_wm_window_set(C, CTX_wm_manager(C)->windows.first);

		ED_editors_init(C);
		DAG_on_visible_update(CTX_data_main(C), TRUE);


		
		BPY_driver_reset();
		BPY_modules_load_user(C);

		CTX_wm_window_set(C, NULL); 


		
		{
			Scene *sce;
			for(sce= G.main->scene.first; sce; sce= sce->id.next) {
				if(sce->r.engine[0] && BLI_findstring(&R_engines, sce->r.engine, offsetof(RenderEngineType, idname)) == NULL) {
					BKE_reportf(reports, RPT_WARNING, "Engine not available: '%s' for scene: %s, an addon may need to be installed or enabled", sce->r.engine, sce->id.name+2);
				}
			}
		}


		
		BKE_reset_undo();
		BKE_write_undo(C, "original");	
		
	}
	else if(retval == BKE_READ_EXOTIC_OK_OTHER)
		BKE_write_undo(C, "Import file");
	else if(retval == BKE_READ_EXOTIC_FAIL_OPEN) {
		BKE_reportf(reports, RPT_ERROR, "Can't read file: \"%s\", %s.", name, errno ? strerror(errno) : "Unable to open the file");
	}
	else if(retval == BKE_READ_EXOTIC_FAIL_FORMAT) {
		BKE_reportf(reports, RPT_ERROR, "File format is not supported in file: \"%s\".", name);
	}
	else if(retval == BKE_READ_EXOTIC_FAIL_PATH) {
		BKE_reportf(reports, RPT_ERROR, "File path invalid: \"%s\".", name);
	}
	else {
		BKE_reportf(reports, RPT_ERROR, "Unknown error loading: \"%s\".", name);
		BLI_assert(!"invalid 'retval'");
	}

	WM_cursor_wait(0);

}





int WM_read_homefile(bContext *C, ReportList *reports, short from_memory)
{
	ListBase wmbase;
	char tstr[FILE_MAXDIR+FILE_MAXFILE];
	int success= 0;
	
	free_ttfont(); 
		
	G.relbase_valid = 0;
	if (!from_memory) {
		char *cfgdir = BLI_get_folder(BLENDER_USER_CONFIG, NULL);
		if (cfgdir) {
			BLI_make_file_string(G.main->name, tstr, cfgdir, BLENDER_STARTUP_FILE);
		} else {
			tstr[0] = '\0';
			from_memory = 1;
			BKE_report(reports, RPT_INFO, "Config directory with "STRINGIFY(BLENDER_STARTUP_FILE)" file not found.");
		}
	}
	
	
	G.fileflags &= ~G_FILE_NO_UI;
	
	
	wm_window_match_init(C, &wmbase); 
	
	if (!from_memory && BLI_exists(tstr)) {
		success = (BKE_read_file(C, tstr, NULL) != BKE_READ_FILE_FAIL);
		
		if(U.themes.first==NULL) {
			printf("\nError: No valid "STRINGIFY(BLENDER_STARTUP_FILE)", fall back to built-in default.\n\n");
			success = 0;
		}
	}
	if(success==0) {
		success = BKE_read_file_from_memory(C, datatoc_startup_blend, datatoc_startup_blend_size, NULL);
		if (wmbase.first == NULL) wm_clear_default_size(C);
	}
	
	
	G.fileflags &= ~G_FILE_RELATIVE_REMAP;

	
	wm_window_match_do(C, &wmbase); 
	WM_check(C); 

	G.main->name[0]= '\0';

	wm_init_userdef(C);
	
	
	if (!G.background) GPU_default_lights();
	
	
	G.save_over = 0;	
	G.fileflags &= ~G_FILE_AUTOPLAY;	

	

	

	BKE_reset_undo();
	BKE_write_undo(C, "original");	

	ED_editors_init(C);
	DAG_on_visible_update(CTX_data_main(C), TRUE);


	if(CTX_py_init_get(C)) {
		
		BPY_string_exec(C, "__import__('addon_utils').reset_all()");

		BPY_driver_reset();
		BPY_modules_load_user(C);
	}


	WM_event_add_notifier(C, NC_WM|ND_FILEREAD, NULL);

	
	if(!G.background) {
		CTX_wm_window_set(C, NULL); 
	}

	return TRUE;
}

int WM_read_homefile_exec(bContext *C, wmOperator *op)
{
	int from_memory= strcmp(op->type->idname, "WM_OT_read_factory_settings") == 0;
	return WM_read_homefile(C, op->reports, from_memory) ? OPERATOR_FINISHED : OPERATOR_CANCELLED;
}

void WM_read_history(void)
{
	char name[FILE_MAX];
	LinkNode *l, *lines;
	struct RecentFile *recent;
	char *line;
	int num;
	char *cfgdir = BLI_get_folder(BLENDER_CONFIG, NULL);

	if (!cfgdir) return;

	BLI_make_file_string("/", name, cfgdir, BLENDER_HISTORY_FILE);

	lines= BLI_read_file_as_lines(name);

	G.recent_files.first = G.recent_files.last = NULL;

	
	for (l= lines, num= 0; l && (num<U.recent_files); l= l->next) {
		line = l->link;
		if (line[0] && BLI_exists(line)) {
			recent = (RecentFile*)MEM_mallocN(sizeof(RecentFile),"RecentFile");
			BLI_addtail(&(G.recent_files), recent);
			recent->filepath = BLI_strdup(line);
			num++;
		}
	}
	
	BLI_free_file_lines(lines);

}

static void write_history(void)
{
	struct RecentFile *recent, *next_recent;
	char name[FILE_MAXDIR+FILE_MAXFILE];
	char *user_config_dir;
	FILE *fp;
	int i;

	
	user_config_dir = BLI_get_folder_create(BLENDER_USER_CONFIG, NULL);
	if(!user_config_dir)
		return;

	BLI_make_file_string("/", name, user_config_dir, BLENDER_HISTORY_FILE);

	recent = G.recent_files.first;
	
	if(!(recent) || (BLI_path_cmp(recent->filepath, G.main->name)!=0)) {
		fp= fopen(name, "w");
		if (fp) {
			
			recent = (RecentFile*)MEM_mallocN(sizeof(RecentFile),"RecentFile");
			recent->filepath = BLI_strdup(G.main->name);
			BLI_addhead(&(G.recent_files), recent);
			
			fprintf(fp, "%s\n", recent->filepath);
			recent = recent->next;
			i=1;
			
			while((i<U.recent_files) && (recent)){
				
				if (BLI_path_cmp(recent->filepath, G.main->name)!=0) {
					fprintf(fp, "%s\n", recent->filepath);
					recent = recent->next;
				}
				else {
					next_recent = recent->next;
					MEM_freeN(recent->filepath);
					BLI_freelinkN(&(G.recent_files), recent);
					recent = next_recent;
				}
				i++;
			}
			fclose(fp);
		}

		
		GHOST_addToSystemRecentFiles(G.main->name);
	}
}

static void do_history(char *name, ReportList *reports)
{
	char tempname1[FILE_MAXDIR+FILE_MAXFILE], tempname2[FILE_MAXDIR+FILE_MAXFILE];
	int hisnr= U.versions;
	
	if(U.versions==0) return;
	if(strlen(name)<2) return;
		
	while(hisnr > 1) {
		BLI_snprintf(tempname1, sizeof(tempname1), "%s%d", name, hisnr-1);
		BLI_snprintf(tempname2, sizeof(tempname2), "%s%d", name, hisnr);
	
		if(BLI_rename(tempname1, tempname2))
			BKE_report(reports, RPT_ERROR, "Unable to make version backup");
			
		hisnr--;
	}

	
	BLI_snprintf(tempname1, sizeof(tempname1), "%s%d", name, hisnr);

	if(BLI_rename(name, tempname1))
		BKE_report(reports, RPT_ERROR, "Unable to make version backup");
}

static ImBuf *blend_file_thumb(Scene *scene, int **thumb_pt)
{
	
	ImBuf *ibuf;
	int *thumb;
	char err_out[256]= "unknown";

	*thumb_pt= NULL;
	
	if(G.background || scene->camera==NULL)
		return NULL;

	
	ibuf= ED_view3d_draw_offscreen_imbuf_simple(scene, BLEN_THUMB_SIZE * 2, BLEN_THUMB_SIZE * 2, IB_rect, OB_SOLID, err_out);
	
	if(ibuf) {		
		float aspect= (scene->r.xsch*scene->r.xasp) / (scene->r.ysch*scene->r.yasp);

		
		IMB_scaleImBuf(ibuf, BLEN_THUMB_SIZE, BLEN_THUMB_SIZE);

		
		IMB_overlayblend_thumb(ibuf->rect, ibuf->x, ibuf->y, aspect);
		
		
		thumb= MEM_mallocN(((2 + (BLEN_THUMB_SIZE * BLEN_THUMB_SIZE))) * sizeof(int), "write_file thumb");

		thumb[0] = BLEN_THUMB_SIZE;
		thumb[1] = BLEN_THUMB_SIZE;

		memcpy(thumb + 2, ibuf->rect, BLEN_THUMB_SIZE * BLEN_THUMB_SIZE * sizeof(int));
	}
	else {
		
		fprintf(stderr, "blend_file_thumb failed to create thumbnail: %s\n", err_out);
		thumb= NULL;
	}
	
	
	*thumb_pt= thumb;
	
	return ibuf;
}


int write_crash_blend(void)
{
	char path[FILE_MAX];
	BLI_strncpy(path, G.main->name, sizeof(path));
	BLI_replace_extension(path, sizeof(path), "_crash.blend");
	if(BLO_write_file(G.main, path, G.fileflags, NULL, NULL)) {
		printf("written: %s\n", path);
		return 1;
	}
	else {
		printf("failed: %s\n", path);
		return 0;
	}
}

int WM_write_file(bContext *C, const char *target, int fileflags, ReportList *reports, int copy)
{
	Library *li;
	int len;
	char di[FILE_MAX];

	int *thumb= NULL;
	ImBuf *ibuf_thumb= NULL;

	len = strlen(target);
	
	if (len == 0) {
		BKE_report(reports, RPT_ERROR, "Path is empty, cannot save");
		return -1;
	}

	if (len >= FILE_MAX) {
		BKE_report(reports, RPT_ERROR, "Path too long, cannot save");
		return -1;
	}
 
	BLI_strncpy(di, target, FILE_MAX);
	BLI_replace_extension(di, FILE_MAX, ".blend");
	
	
	
	for (li= G.main->library.first; li; li= li->id.next) {
		if (BLI_path_cmp(li->filepath, di) == 0) {
			BKE_reportf(reports, RPT_ERROR, "Can't overwrite used library '%.200s'", di);
			return -1;
		}
	}

	

	if (G.fileflags & G_AUTOPACK) {
		packAll(G.main, reports);
	}
	
	ED_object_exit_editmode(C, EM_DO_UNDO);
	ED_sculpt_force_update(C);

	
	WM_cursor_wait(1);
	
	
	ibuf_thumb= blend_file_thumb(CTX_data_scene(C), &thumb);

	
	do_history(di, reports);

	if (BLO_write_file(CTX_data_main(C), di, fileflags, reports, thumb)) {
		if(!copy) {
			G.relbase_valid = 1;
			BLI_strncpy(G.main->name, di, sizeof(G.main->name));	
	
			G.save_over = 1; 
		}

		if(fileflags & G_FILE_COMPRESS) G.fileflags |= G_FILE_COMPRESS;
		else G.fileflags &= ~G_FILE_COMPRESS;
		
		if(fileflags & G_FILE_AUTOPLAY) G.fileflags |= G_FILE_AUTOPLAY;
		else G.fileflags &= ~G_FILE_AUTOPLAY;

		write_history();

		
		if (ibuf_thumb) {
			ibuf_thumb= IMB_thumb_create(di, THB_NORMAL, THB_SOURCE_BLEND, ibuf_thumb);
			IMB_freeImBuf(ibuf_thumb);
		}

		if(thumb) MEM_freeN(thumb);
	}
	else {
		if(ibuf_thumb) IMB_freeImBuf(ibuf_thumb);
		if(thumb) MEM_freeN(thumb);
		
		WM_cursor_wait(0);
		return -1;
	}

	WM_cursor_wait(0);
	
	return 0;
}


int WM_write_homefile(bContext *C, wmOperator *op)
{
	wmWindowManager *wm= CTX_wm_manager(C);
	wmWindow *win= CTX_wm_window(C);
	char tstr[FILE_MAXDIR+FILE_MAXFILE];
	int fileflags;
	
	
	if(win->screen->temp)
		wm_window_close(C, wm, win);
	
	BLI_make_file_string("/", tstr, BLI_get_folder_create(BLENDER_USER_CONFIG, NULL), BLENDER_STARTUP_FILE);
	printf("trying to save homefile at %s ", tstr);
	
	
	fileflags = G.fileflags & ~(G_FILE_COMPRESS | G_FILE_AUTOPLAY | G_FILE_LOCK | G_FILE_SIGN);

	if(BLO_write_file(CTX_data_main(C), tstr, fileflags, op->reports, NULL) == 0) {
		printf("fail\n");
		return OPERATOR_CANCELLED;
	}
	
	printf("ok\n");

	G.save_over= 0;

	return OPERATOR_FINISHED;
}



void wm_autosave_location(char *filename)
{
	char pidstr[32];

	char *savedir;


	BLI_snprintf(pidstr, sizeof(pidstr), "%d.blend", abs(getpid()));


	
	if (!BLI_exists(U.tempdir)) {
		savedir = BLI_get_folder_create(BLENDER_USER_AUTOSAVE, NULL);
		BLI_make_file_string("/", filename, savedir, pidstr);
		return;
	}

	
	BLI_make_file_string("/", filename, U.tempdir, pidstr);
}

void WM_autosave_init(wmWindowManager *wm)
{
	wm_autosave_timer_ended(wm);

	if(U.flag & USER_AUTOSAVE)
		wm->autosavetimer= WM_event_add_timer(wm, NULL, TIMERAUTOSAVE, U.savetime*60.0);
}

void wm_autosave_timer(const bContext *C, wmWindowManager *wm, wmTimer *UNUSED(wt))
{
	wmWindow *win;
	wmEventHandler *handler;
	char filename[FILE_MAX];
	int fileflags;

	WM_event_remove_timer(wm, NULL, wm->autosavetimer);

	
	for(win=wm->windows.first; win; win=win->next) {
		for(handler=win->modalhandlers.first; handler; handler=handler->next) {
			if(handler->op) {
				wm->autosavetimer= WM_event_add_timer(wm, NULL, TIMERAUTOSAVE, 10.0);
				return;
			}
		}
	}
	
	wm_autosave_location(filename);

	
	fileflags = G.fileflags & ~(G_FILE_COMPRESS|G_FILE_AUTOPLAY |G_FILE_LOCK|G_FILE_SIGN);

	
	BLO_write_file(CTX_data_main(C), filename, fileflags, NULL, NULL);

	
	wm->autosavetimer= WM_event_add_timer(wm, NULL, TIMERAUTOSAVE, U.savetime*60.0);
}

void wm_autosave_timer_ended(wmWindowManager *wm)
{
	if(wm->autosavetimer) {
		WM_event_remove_timer(wm, NULL, wm->autosavetimer);
		wm->autosavetimer= NULL;
	}
}

void wm_autosave_delete(void)
{
	char filename[FILE_MAX];
	
	wm_autosave_location(filename);

	if(BLI_exists(filename)) {
		char str[FILE_MAXDIR+FILE_MAXFILE];
		BLI_make_file_string("/", str, U.tempdir, "quit.blend");

		
		if(U.uiflag & USER_GLOBALUNDO) BLI_delete(filename, 0, 0);
		else BLI_rename(filename, str);
	}
}

void wm_autosave_read(bContext *C, ReportList *reports)
{
	char filename[FILE_MAX];

	wm_autosave_location(filename);
	WM_read_file(C, filename, reports);
}

