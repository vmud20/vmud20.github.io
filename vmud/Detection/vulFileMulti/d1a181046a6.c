





	#include <unistd.h> 

	#include <io.h> 
	#define open _open
	#define read _read
	#define close _close
	#define write _write
















































Global G;
UserDef U;

short ENDIAN_ORDER;

static char versionstr[48]= "";




void free_blender(void)
{
	
	free_main(G.main);
	G.main= NULL;

	BKE_spacetypes_free();		
	
	IMB_exit();
	seq_stripelem_cache_destruct();
	
	free_nodesystem();	
}

void initglobals(void)
{
	memset(&G, 0, sizeof(Global));
	
	U.savetime= 1;

	G.main= MEM_callocN(sizeof(Main), "initglobals");

	strcpy(G.ima, "//");

	ENDIAN_ORDER= 1;
	ENDIAN_ORDER= (((char*)&ENDIAN_ORDER)[0])? L_ENDIAN: B_ENDIAN;

	if(BLENDER_SUBVERSION)
		BLI_snprintf(versionstr, sizeof(versionstr), "www.blender.org %d.%d", BLENDER_VERSION, BLENDER_SUBVERSION);
	else BLI_snprintf(versionstr, sizeof(versionstr), "www.blender.org %d", BLENDER_VERSION);


	G.windowstate = G_WINDOWSTATE_USERDEF;


	G.charstart = 0x0000;
	G.charmin = 0x0000;
	G.charmax = 0xffff;
	
	G.f |= G_SCRIPT_AUTOEXEC;
}



static void clear_global(void) 
{


	fastshade_free_render();	
	free_main(G.main);			
	


	G.main= NULL;
}


static void clean_paths(Main *main)
{
	struct BPathIterator *bpi;
	char filepath_expanded[1024];
	Scene *scene;

	for(BLI_bpathIterator_init(&bpi, main, main->name, BPATH_USE_PACKED); !BLI_bpathIterator_isDone(bpi); BLI_bpathIterator_step(bpi)) {
		BLI_bpathIterator_getPath(bpi, filepath_expanded);

		BLI_clean(filepath_expanded);

		BLI_bpathIterator_setPath(bpi, filepath_expanded);
	}

	BLI_bpathIterator_free(bpi);

	for(scene= main->scene.first; scene; scene= scene->id.next) {
		BLI_clean(scene->r.backbuf);
		BLI_clean(scene->r.pic);
	}
}






static void setup_app_data(bContext *C, BlendFileData *bfd, const char *filename) 
{
	bScreen *curscreen= NULL;
	Scene *curscene= NULL;
	int recover;
	char mode;

	
	if(bfd->main->screen.first==NULL) mode= 'u';
	else if(G.fileflags & G_FILE_NO_UI) mode= 'n';
	else mode= 0;

	recover= (G.fileflags & G_FILE_RECOVER);

	
	if(mode != 'u') {
		clean_paths(bfd->main);
	}

	
	
	
	if(mode) {
		
		extern void lib_link_screen_restore(Main *, bScreen *, Scene *);
		
		SWAP(ListBase, G.main->wm, bfd->main->wm);
		SWAP(ListBase, G.main->screen, bfd->main->screen);
		SWAP(ListBase, G.main->script, bfd->main->script);
		
		
		curscreen= CTX_wm_screen(C);
		
		curscene= bfd->curscene;
		if(curscene==NULL) curscene= bfd->main->scene.first;
		
		if(curscreen) curscreen->scene= curscene; 

		
		lib_link_screen_restore(bfd->main, curscreen, curscene);
	}
	
	

	clear_global();	
	
	G.main= bfd->main;

	CTX_data_main_set(C, G.main);
	
	if (bfd->user) {
		
		
		BKE_userdef_free();
		
		U= *bfd->user;
		MEM_freeN(bfd->user);
	}
	
	
	if(mode) {
		
		CTX_data_scene_set(C, curscene);
	}
	else {
		G.winpos= bfd->winpos;
		G.displaymode= bfd->displaymode;
		G.fileflags= bfd->fileflags;
		CTX_wm_manager_set(C, bfd->main->wm.first);
		CTX_wm_screen_set(C, bfd->curscreen);
		CTX_data_scene_set(C, bfd->curscreen->scene);
		CTX_wm_area_set(C, NULL);
		CTX_wm_region_set(C, NULL);
		CTX_wm_menu_set(C, NULL);
	}
	
	
	if(CTX_data_scene(C)==NULL) {
		CTX_data_scene_set(C, bfd->main->scene.first);
		CTX_wm_screen(C)->scene= CTX_data_scene(C);
		curscene= CTX_data_scene(C);
	}

	
	if(G.f != bfd->globalf) {
		const int flags_keep= (G_DEBUG | G_SWAP_EXCHANGE | G_SCRIPT_AUTOEXEC | G_SCRIPT_OVERRIDE_PREF);
		bfd->globalf= (bfd->globalf & ~flags_keep) | (G.f & flags_keep);
	}


	G.f= bfd->globalf;

	if (!G.background) {
		
	}
	
	
	
	if (G.main->versionfile < 250)
		do_versions_ipos_to_animato(G.main);
	
	if(recover && bfd->filename[0] && G.relbase_valid) {
		
		filename= bfd->filename;
	}

	else if (!G.relbase_valid) {
		
		filename="";
	}

	
	
	if(G.main->name != filename)
		BLI_strncpy(G.main->name, filename, FILE_MAX);

	
	set_scene_bg(G.main, CTX_data_scene(C));
	
	MEM_freeN(bfd);
}

static int handle_subversion_warning(Main *main)
{
	if(main->minversionfile > BLENDER_VERSION || (main->minversionfile == BLENDER_VERSION && main->minsubversionfile > BLENDER_SUBVERSION)) {

		
		char str[128];
		
		BLI_snprintf(str, sizeof(str), "File written by newer Blender binary: %d.%d , expect loss of data!", main->minversionfile, main->minsubversionfile);

	}
	return 1;
}

void BKE_userdef_free(void)
{
	wmKeyMap *km;
	wmKeyMapItem *kmi;

	for(km=U.keymaps.first; km; km=km->next) {
		for(kmi=km->items.first; kmi; kmi=kmi->next) {
			if(kmi->properties) {
				IDP_FreeProperty(kmi->properties);
				MEM_freeN(kmi->properties);
			}
			if(kmi->ptr)
				MEM_freeN(kmi->ptr);
		}

		BLI_freelistN(&km->items);
	}
	
	BLI_freelistN(&U.uistyles);
	BLI_freelistN(&U.uifonts);
	BLI_freelistN(&U.themes);
	BLI_freelistN(&U.keymaps);
	BLI_freelistN(&U.addons);
}

int BKE_read_file(bContext *C, const char *dir, ReportList *reports) 
{
	BlendFileData *bfd;
	int retval= BKE_READ_FILE_OK;

	if(strstr(dir, BLENDER_STARTUP_FILE)==NULL) 
		printf("read blend: %s\n", dir);

	bfd= BLO_read_from_file(dir, reports);
	if (bfd) {
		if(bfd->user) retval= BKE_READ_FILE_OK_USERPREFS;
		
		if(0==handle_subversion_warning(bfd->main)) {
			free_main(bfd->main);
			MEM_freeN(bfd);
			bfd= NULL;
			retval= BKE_READ_FILE_FAIL;
		}
		else setup_app_data(C, bfd, dir);
	} 
	else BKE_reports_prependf(reports, "Loading %s failed: ", dir);
		
	return (bfd?retval:BKE_READ_FILE_FAIL);
}

int BKE_read_file_from_memory(bContext *C, char* filebuf, int filelength, ReportList *reports)
{
	BlendFileData *bfd;

	bfd= BLO_read_from_memory(filebuf, filelength, reports);
	if (bfd)
		setup_app_data(C, bfd, "<memory2>");
	else BKE_reports_prepend(reports, "Loading failed: ");

	return (bfd?1:0);
}


int BKE_read_file_from_memfile(bContext *C, MemFile *memfile, ReportList *reports)
{
	BlendFileData *bfd;

	bfd= BLO_read_from_memfile(CTX_data_main(C), G.main->name, memfile, reports);
	if (bfd)
		setup_app_data(C, bfd, "<memory1>");
	else BKE_reports_prepend(reports, "Loading failed: ");

	return (bfd?1:0);
}




static void (*blender_test_break_cb)(void)= NULL;

void set_blender_test_break_cb(void (*func)(void) )
{
	blender_test_break_cb= func;
}


int blender_test_break(void)
{
	if (!G.background) {
		if (blender_test_break_cb)
			blender_test_break_cb();
	}
	
	return (G.afbreek==1);
}







typedef struct UndoElem {
	struct UndoElem *next, *prev;
	char str[FILE_MAXDIR+FILE_MAXFILE];
	char name[MAXUNDONAME];
	MemFile memfile;
	uintptr_t undosize;
} UndoElem;

static ListBase undobase={NULL, NULL};
static UndoElem *curundo= NULL;


static int read_undosave(bContext *C, UndoElem *uel)
{
	char mainstr[sizeof(G.main->name)];
	int success=0, fileflags;
	
	
	WM_jobs_stop_all(CTX_wm_manager(C));

	BLI_strncpy(mainstr, G.main->name, sizeof(mainstr));	

	fileflags= G.fileflags;
	G.fileflags |= G_FILE_NO_UI;

	if(UNDO_DISK) 
		success= (BKE_read_file(C, uel->str, NULL) != BKE_READ_FILE_FAIL);
	else success= BKE_read_file_from_memfile(C, &uel->memfile, NULL);

	
	BLI_strncpy(G.main->name, mainstr, sizeof(G.main->name)); 
	G.fileflags= fileflags;

	if(success) {
		
		DAG_on_visible_update(G.main, FALSE);
	}

	return success;
}


void BKE_write_undo(bContext *C, const char *name)
{
	uintptr_t maxmem, totmem, memused;
	int nr, success;
	UndoElem *uel;
	
	if( (U.uiflag & USER_GLOBALUNDO)==0) return;
	if( U.undosteps==0) return;
	
	
	while(undobase.last != curundo) {
		uel= undobase.last;
		BLI_remlink(&undobase, uel);
		BLO_free_memfile(&uel->memfile);
		MEM_freeN(uel);
	}
	
	
	curundo= uel= MEM_callocN(sizeof(UndoElem), "undo file");
	strncpy(uel->name, name, MAXUNDONAME-1);
	BLI_addtail(&undobase, uel);
	
	
	nr= 0;
	uel= undobase.last;
	while(uel) {
		nr++;
		if(nr==U.undosteps) break;
		uel= uel->prev;
	}
	if(uel) {
		while(undobase.first!=uel) {
			UndoElem *first= undobase.first;
			BLI_remlink(&undobase, first);
			
			BLO_merge_memfile(&first->memfile, &first->next->memfile);
			MEM_freeN(first);
		}
	}


	
	if(UNDO_DISK) {
		static int counter= 0;
		char tstr[FILE_MAXDIR+FILE_MAXFILE];
		char numstr[32];
		
		
		counter++;
		counter= counter % U.undosteps;	
	
		BLI_snprintf(numstr, sizeof(numstr), "%d.blend", counter);
		BLI_make_file_string("/", tstr, btempdir, numstr);
	
		success= BLO_write_file(CTX_data_main(C), tstr, G.fileflags, NULL, NULL);
		
		BLI_strncpy(curundo->str, tstr, sizeof(curundo->str));
	}
	else {
		MemFile *prevfile=NULL;
		
		if(curundo->prev) prevfile= &(curundo->prev->memfile);
		
		memused= MEM_get_memory_in_use();
		success= BLO_write_file_mem(CTX_data_main(C), prevfile, &curundo->memfile, G.fileflags);
		curundo->undosize= MEM_get_memory_in_use() - memused;
	}

	if(U.undomemory != 0) {
		
		totmem= 0;
		maxmem= ((uintptr_t)U.undomemory)*1024*1024;

		
		uel= undobase.last;
		while(uel && uel->prev) {
			totmem+= uel->undosize;
			if(totmem>maxmem) break;
			uel= uel->prev;
		}

		if(uel) {
			if(uel->prev && uel->prev->prev)
				uel= uel->prev;

			while(undobase.first!=uel) {
				UndoElem *first= undobase.first;
				BLI_remlink(&undobase, first);
				
				BLO_merge_memfile(&first->memfile, &first->next->memfile);
				MEM_freeN(first);
			}
		}
	}
}


void BKE_undo_step(bContext *C, int step)
{
	
	if(step==0) {
		read_undosave(C, curundo);
	}
	else if(step==1) {
		
		if(curundo==NULL || curundo->prev==NULL) ; 
		else {
			if(G.f & G_DEBUG) printf("undo %s\n", curundo->name);
			curundo= curundo->prev;
			read_undosave(C, curundo);
		}
	}
	else {
		
		
		
		if(curundo==NULL || curundo->next==NULL) ; 
		else {
			read_undosave(C, curundo->next);
			curundo= curundo->next;
			if(G.f & G_DEBUG) printf("redo %s\n", curundo->name);
		}
	}
}

void BKE_reset_undo(void)
{
	UndoElem *uel;
	
	uel= undobase.first;
	while(uel) {
		BLO_free_memfile(&uel->memfile);
		uel= uel->next;
	}
	
	BLI_freelistN(&undobase);
	curundo= NULL;
}


void BKE_undo_number(bContext *C, int nr)
{
	UndoElem *uel;
	int a=1;
	
	for(uel= undobase.first; uel; uel= uel->next, a++) {
		if(a==nr) break;
	}
	curundo= uel;
	BKE_undo_step(C, 0);
}


void BKE_undo_name(bContext *C, const char *name)
{
	UndoElem *uel;

	for(uel= undobase.last; uel; uel= uel->prev)
		if(strcmp(name, uel->name)==0)
			break;

	if(uel && uel->prev) {
		curundo= uel->prev;
		BKE_undo_step(C, 0);
	}
}


int BKE_undo_valid(const char *name)
{
	if(name) {
		UndoElem *uel;
		
		for(uel= undobase.last; uel; uel= uel->prev)
			if(strcmp(name, uel->name)==0)
				break;
		
		return uel && uel->prev;
	}
	
	return undobase.last != undobase.first;
}


char *BKE_undo_menu_string(void)
{
	UndoElem *uel;
	DynStr *ds= BLI_dynstr_new();
	char *menu;

	BLI_dynstr_append(ds, "Global Undo History %t");
	
	for(uel= undobase.first; uel; uel= uel->next) {
		BLI_dynstr_append(ds, "|");
		BLI_dynstr_append(ds, uel->name);
	}

	menu= BLI_dynstr_get_cstring(ds);
	BLI_dynstr_free(ds);

	return menu;
}

	
void BKE_undo_save_quit(void)
{
	UndoElem *uel;
	MemFileChunk *chunk;
	int file;
	char str[FILE_MAXDIR+FILE_MAXFILE];
	
	if( (U.uiflag & USER_GLOBALUNDO)==0) return;
	
	uel= curundo;
	if(uel==NULL) {
		printf("No undo buffer to save recovery file\n");
		return;
	}
	
	
	if(undobase.first==undobase.last) return;
		
	BLI_make_file_string("/", str, btempdir, "quit.blend");

	file = open(str,O_BINARY+O_WRONLY+O_CREAT+O_TRUNC, 0666);
	if(file == -1) {
		
		return;
	}

	chunk= uel->memfile.chunks.first;
	while(chunk) {
		if( write(file, chunk->buf, chunk->size) != chunk->size) break;
		chunk= chunk->next;
	}
	
	close(file);
	
	if(chunk) ; 
	else printf("Saved session recovery to %s\n", str);
}


Main *BKE_undo_get_main(Scene **scene)
{
	Main *mainp= NULL;
	BlendFileData *bfd= BLO_read_from_memfile(G.main, G.main->name, &curundo->memfile, NULL);
	
	if(bfd) {
		mainp= bfd->main;
		if(scene)
			*scene= bfd->curscene;
		
		MEM_freeN(bfd);
	}
	
	return mainp;
}

