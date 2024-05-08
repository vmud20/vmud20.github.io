


__FBSDID("$FreeBSD$");











































int kld_debug = 0;
SYSCTL_INT(_debug, OID_AUTO, kld_debug, CTLFLAG_RWTUN, &kld_debug, 0, "Set various levels of KLD debug");



const int kld_off_address = offsetof(struct linker_file, address);
const int kld_off_filename = offsetof(struct linker_file, filename);
const int kld_off_pathname = offsetof(struct linker_file, pathname);
const int kld_off_next = offsetof(struct linker_file, link.tqe_next);


static const char 	*linker_basename(const char *path);


static linker_file_t linker_find_file_by_name(const char* _filename);


static linker_file_t linker_find_file_by_id(int _fileid);


SET_DECLARE(modmetadata_set, struct mod_metadata);

MALLOC_DEFINE(M_LINKER, "linker", "kernel linker");

linker_file_t linker_kernel_file;

static struct sx kld_sx;	


static int loadcnt;

static linker_class_list_t classes;
static linker_file_list_t linker_files;
static int next_file_id = 1;
static int linker_no_more_classes = 0;

















typedef TAILQ_HEAD(, modlist) modlisthead_t;
struct modlist {
	TAILQ_ENTRY(modlist) link;	
	linker_file_t   container;
	const char 	*name;
	int             version;
};
typedef struct modlist *modlist_t;
static modlisthead_t found_modules;

static int	linker_file_add_dependency(linker_file_t file, linker_file_t dep);
static caddr_t	linker_file_lookup_symbol_internal(linker_file_t file, const char* name, int deps);
static int	linker_load_module(const char *kldname, const char *modname, struct linker_file *parent, const struct mod_depend *verinfo, struct linker_file **lfpp);

static modlist_t modlist_lookup2(const char *name, const struct mod_depend *verinfo);

static void linker_init(void *arg)
{

	sx_init(&kld_sx, "kernel linker");
	TAILQ_INIT(&classes);
	TAILQ_INIT(&linker_files);
}

SYSINIT(linker, SI_SUB_KLD, SI_ORDER_FIRST, linker_init, 0);

static void linker_stop_class_add(void *arg)
{

	linker_no_more_classes = 1;
}

SYSINIT(linker_class, SI_SUB_KLD, SI_ORDER_ANY, linker_stop_class_add, NULL);

int linker_add_class(linker_class_t lc)
{

	
	if (linker_no_more_classes == 1)
		return (EPERM);
	kobj_class_compile((kobj_class_t) lc);
	((kobj_class_t)lc)->refs++;	
	TAILQ_INSERT_TAIL(&classes, lc, link);
	return (0);
}

static void linker_file_sysinit(linker_file_t lf)
{
	struct sysinit **start, **stop, **sipp, **xipp, *save;

	KLD_DPF(FILE, ("linker_file_sysinit: calling SYSINITs for %s\n", lf->filename));

	sx_assert(&kld_sx, SA_XLOCKED);

	if (linker_file_lookup_set(lf, "sysinit_set", &start, &stop, NULL) != 0)
		return;
	
	for (sipp = start; sipp < stop; sipp++) {
		for (xipp = sipp + 1; xipp < stop; xipp++) {
			if ((*sipp)->subsystem < (*xipp)->subsystem || ((*sipp)->subsystem == (*xipp)->subsystem && (*sipp)->order <= (*xipp)->order))

				continue;	
			save = *sipp;
			*sipp = *xipp;
			*xipp = save;
		}
	}

	
	sx_xunlock(&kld_sx);
	mtx_lock(&Giant);
	for (sipp = start; sipp < stop; sipp++) {
		if ((*sipp)->subsystem == SI_SUB_DUMMY)
			continue;	

		
		(*((*sipp)->func)) ((*sipp)->udata);
	}
	mtx_unlock(&Giant);
	sx_xlock(&kld_sx);
}

static void linker_file_sysuninit(linker_file_t lf)
{
	struct sysinit **start, **stop, **sipp, **xipp, *save;

	KLD_DPF(FILE, ("linker_file_sysuninit: calling SYSUNINITs for %s\n", lf->filename));

	sx_assert(&kld_sx, SA_XLOCKED);

	if (linker_file_lookup_set(lf, "sysuninit_set", &start, &stop, NULL) != 0)
		return;

	
	for (sipp = start; sipp < stop; sipp++) {
		for (xipp = sipp + 1; xipp < stop; xipp++) {
			if ((*sipp)->subsystem > (*xipp)->subsystem || ((*sipp)->subsystem == (*xipp)->subsystem && (*sipp)->order >= (*xipp)->order))

				continue;	
			save = *sipp;
			*sipp = *xipp;
			*xipp = save;
		}
	}

	
	sx_xunlock(&kld_sx);
	mtx_lock(&Giant);
	for (sipp = start; sipp < stop; sipp++) {
		if ((*sipp)->subsystem == SI_SUB_DUMMY)
			continue;	

		
		(*((*sipp)->func)) ((*sipp)->udata);
	}
	mtx_unlock(&Giant);
	sx_xlock(&kld_sx);
}

static void linker_file_register_sysctls(linker_file_t lf, bool enable)
{
	struct sysctl_oid **start, **stop, **oidp;

	KLD_DPF(FILE, ("linker_file_register_sysctls: registering SYSCTLs for %s\n", lf->filename));


	sx_assert(&kld_sx, SA_XLOCKED);

	if (linker_file_lookup_set(lf, "sysctl_set", &start, &stop, NULL) != 0)
		return;

	sx_xunlock(&kld_sx);
	sysctl_wlock();
	for (oidp = start; oidp < stop; oidp++) {
		if (enable)
			sysctl_register_oid(*oidp);
		else sysctl_register_disabled_oid(*oidp);
	}
	sysctl_wunlock();
	sx_xlock(&kld_sx);
}

static void linker_file_enable_sysctls(linker_file_t lf)
{
	struct sysctl_oid **start, **stop, **oidp;

	KLD_DPF(FILE, ("linker_file_enable_sysctls: enable SYSCTLs for %s\n", lf->filename));


	sx_assert(&kld_sx, SA_XLOCKED);

	if (linker_file_lookup_set(lf, "sysctl_set", &start, &stop, NULL) != 0)
		return;

	sx_xunlock(&kld_sx);
	sysctl_wlock();
	for (oidp = start; oidp < stop; oidp++)
		sysctl_enable_oid(*oidp);
	sysctl_wunlock();
	sx_xlock(&kld_sx);
}

static void linker_file_unregister_sysctls(linker_file_t lf)
{
	struct sysctl_oid **start, **stop, **oidp;

	KLD_DPF(FILE, ("linker_file_unregister_sysctls: unregistering SYSCTLs" " for %s\n", lf->filename));

	sx_assert(&kld_sx, SA_XLOCKED);

	if (linker_file_lookup_set(lf, "sysctl_set", &start, &stop, NULL) != 0)
		return;

	sx_xunlock(&kld_sx);
	sysctl_wlock();
	for (oidp = start; oidp < stop; oidp++)
		sysctl_unregister_oid(*oidp);
	sysctl_wunlock();
	sx_xlock(&kld_sx);
}

static int linker_file_register_modules(linker_file_t lf)
{
	struct mod_metadata **start, **stop, **mdp;
	const moduledata_t *moddata;
	int first_error, error;

	KLD_DPF(FILE, ("linker_file_register_modules: registering modules" " in %s\n", lf->filename));

	sx_assert(&kld_sx, SA_XLOCKED);

	if (linker_file_lookup_set(lf, "modmetadata_set", &start, &stop, NULL) != 0) {
		
		if (lf == linker_kernel_file) {
			start = SET_BEGIN(modmetadata_set);
			stop = SET_LIMIT(modmetadata_set);
		} else return (0);
	}
	first_error = 0;
	for (mdp = start; mdp < stop; mdp++) {
		if ((*mdp)->md_type != MDT_MODULE)
			continue;
		moddata = (*mdp)->md_data;
		KLD_DPF(FILE, ("Registering module %s in %s\n", moddata->name, lf->filename));
		error = module_register(moddata, lf);
		if (error) {
			printf("Module %s failed to register: %d\n", moddata->name, error);
			if (first_error == 0)
				first_error = error;
		}
	}
	return (first_error);
}

static void linker_init_kernel_modules(void)
{

	sx_xlock(&kld_sx);
	linker_file_register_modules(linker_kernel_file);
	sx_xunlock(&kld_sx);
}

SYSINIT(linker_kernel, SI_SUB_KLD, SI_ORDER_ANY, linker_init_kernel_modules, 0);

static int linker_load_file(const char *filename, linker_file_t *result)
{
	linker_class_t lc;
	linker_file_t lf;
	int foundfile, error, modules;

	
	if (prison0.pr_securelevel > 0)
		return (EPERM);

	sx_assert(&kld_sx, SA_XLOCKED);
	lf = linker_find_file_by_name(filename);
	if (lf) {
		KLD_DPF(FILE, ("linker_load_file: file %s is already loaded," " incrementing refs\n", filename));
		*result = lf;
		lf->refs++;
		return (0);
	}
	foundfile = 0;
	error = 0;

	
	TAILQ_FOREACH(lc, &classes, link) {
		KLD_DPF(FILE, ("linker_load_file: trying to load %s\n", filename));
		error = LINKER_LOAD_FILE(lc, filename, &lf);
		
		if (error != ENOENT)
			foundfile = 1;
		if (lf) {
			error = linker_file_register_modules(lf);
			if (error == EEXIST) {
				linker_file_unload(lf, LINKER_UNLOAD_FORCE);
				return (error);
			}
			modules = !TAILQ_EMPTY(&lf->modules);
			linker_file_register_sysctls(lf, false);
			linker_file_sysinit(lf);
			lf->flags |= LINKER_FILE_LINKED;

			
			if (modules && TAILQ_EMPTY(&lf->modules)) {
				linker_file_unload(lf, LINKER_UNLOAD_FORCE);
				return (ENOEXEC);
			}
			linker_file_enable_sysctls(lf);
			EVENTHANDLER_INVOKE(kld_load, lf);
			*result = lf;
			return (0);
		}
	}
	
	if (foundfile) {

		
		if (error == ENOSYS)
			printf("%s: %s - unsupported file type\n", __func__, filename);

		
		if (error != EEXIST)
			error = ENOEXEC;
	} else error = ENOENT;
	return (error);
}

int linker_reference_module(const char *modname, struct mod_depend *verinfo, linker_file_t *result)

{
	modlist_t mod;
	int error;

	sx_xlock(&kld_sx);
	if ((mod = modlist_lookup2(modname, verinfo)) != NULL) {
		*result = mod->container;
		(*result)->refs++;
		sx_xunlock(&kld_sx);
		return (0);
	}

	error = linker_load_module(NULL, modname, NULL, verinfo, result);
	sx_xunlock(&kld_sx);
	return (error);
}

int linker_release_module(const char *modname, struct mod_depend *verinfo, linker_file_t lf)

{
	modlist_t mod;
	int error;

	sx_xlock(&kld_sx);
	if (lf == NULL) {
		KASSERT(modname != NULL, ("linker_release_module: no file or name"));
		mod = modlist_lookup2(modname, verinfo);
		if (mod == NULL) {
			sx_xunlock(&kld_sx);
			return (ESRCH);
		}
		lf = mod->container;
	} else KASSERT(modname == NULL && verinfo == NULL, ("linker_release_module: both file and name"));

	error =	linker_file_unload(lf, LINKER_UNLOAD_NORMAL);
	sx_xunlock(&kld_sx);
	return (error);
}

static linker_file_t linker_find_file_by_name(const char *filename)
{
	linker_file_t lf;
	char *koname;

	koname = malloc(strlen(filename) + 4, M_LINKER, M_WAITOK);
	sprintf(koname, "%s.ko", filename);

	sx_assert(&kld_sx, SA_XLOCKED);
	TAILQ_FOREACH(lf, &linker_files, link) {
		if (strcmp(lf->filename, koname) == 0)
			break;
		if (strcmp(lf->filename, filename) == 0)
			break;
	}
	free(koname, M_LINKER);
	return (lf);
}

static linker_file_t linker_find_file_by_id(int fileid)
{
	linker_file_t lf;

	sx_assert(&kld_sx, SA_XLOCKED);
	TAILQ_FOREACH(lf, &linker_files, link)
		if (lf->id == fileid && lf->flags & LINKER_FILE_LINKED)
			break;
	return (lf);
}

int linker_file_foreach(linker_predicate_t *predicate, void *context)
{
	linker_file_t lf;
	int retval = 0;

	sx_xlock(&kld_sx);
	TAILQ_FOREACH(lf, &linker_files, link) {
		retval = predicate(lf, context);
		if (retval != 0)
			break;
	}
	sx_xunlock(&kld_sx);
	return (retval);
}

linker_file_t linker_make_file(const char *pathname, linker_class_t lc)
{
	linker_file_t lf;
	const char *filename;

	if (!cold)
		sx_assert(&kld_sx, SA_XLOCKED);
	filename = linker_basename(pathname);

	KLD_DPF(FILE, ("linker_make_file: new file, filename='%s' for pathname='%s'\n", filename, pathname));
	lf = (linker_file_t)kobj_create((kobj_class_t)lc, M_LINKER, M_WAITOK);
	if (lf == NULL)
		return (NULL);
	lf->ctors_addr = 0;
	lf->ctors_size = 0;
	lf->refs = 1;
	lf->userrefs = 0;
	lf->flags = 0;
	lf->filename = strdup(filename, M_LINKER);
	lf->pathname = strdup(pathname, M_LINKER);
	LINKER_GET_NEXT_FILE_ID(lf->id);
	lf->ndeps = 0;
	lf->deps = NULL;
	lf->loadcnt = ++loadcnt;
	STAILQ_INIT(&lf->common);
	TAILQ_INIT(&lf->modules);
	TAILQ_INSERT_TAIL(&linker_files, lf, link);
	return (lf);
}

int linker_file_unload(linker_file_t file, int flags)
{
	module_t mod, next;
	modlist_t ml, nextml;
	struct common_symbol *cp;
	int error, i;

	
	if (prison0.pr_securelevel > 0)
		return (EPERM);

	sx_assert(&kld_sx, SA_XLOCKED);
	KLD_DPF(FILE, ("linker_file_unload: lf->refs=%d\n", file->refs));

	
	if (file->refs > 1) {
		file->refs--;
		return (0);
	}

	
	error = 0;
	EVENTHANDLER_INVOKE(kld_unload_try, file, &error);
	if (error != 0)
		return (EBUSY);

	KLD_DPF(FILE, ("linker_file_unload: file is unloading," " informing modules\n"));

	
	MOD_SLOCK;
	for (mod = TAILQ_FIRST(&file->modules); mod;
	     mod = module_getfnext(mod)) {

		error = module_quiesce(mod);
		if (error != 0 && flags != LINKER_UNLOAD_FORCE) {
			KLD_DPF(FILE, ("linker_file_unload: module %s" " vetoed unload\n", module_getname(mod)));
			
			MOD_SUNLOCK;
			return (error);
		}
	}
	MOD_SUNLOCK;

	
	MOD_XLOCK;
	for (mod = TAILQ_FIRST(&file->modules); mod; mod = next) {
		next = module_getfnext(mod);
		MOD_XUNLOCK;

		
		if ((error = module_unload(mod)) != 0) {

			MOD_SLOCK;
			KLD_DPF(FILE, ("linker_file_unload: module %s" " failed unload\n", module_getname(mod)));
			MOD_SUNLOCK;

			return (error);
		}
		MOD_XLOCK;
		module_release(mod);
	}
	MOD_XUNLOCK;

	TAILQ_FOREACH_SAFE(ml, &found_modules, link, nextml) {
		if (ml->container == file) {
			TAILQ_REMOVE(&found_modules, ml, link);
			free(ml, M_LINKER);
		}
	}

	
	if (file->flags & LINKER_FILE_LINKED) {
		file->flags &= ~LINKER_FILE_LINKED;
		linker_file_unregister_sysctls(file);
		linker_file_sysuninit(file);
	}
	TAILQ_REMOVE(&linker_files, file, link);

	if (file->deps) {
		for (i = 0; i < file->ndeps; i++)
			linker_file_unload(file->deps[i], flags);
		free(file->deps, M_LINKER);
		file->deps = NULL;
	}
	while ((cp = STAILQ_FIRST(&file->common)) != NULL) {
		STAILQ_REMOVE_HEAD(&file->common, link);
		free(cp, M_LINKER);
	}

	LINKER_UNLOAD(file);

	EVENTHANDLER_INVOKE(kld_unload, file->filename, file->address, file->size);

	if (file->filename) {
		free(file->filename, M_LINKER);
		file->filename = NULL;
	}
	if (file->pathname) {
		free(file->pathname, M_LINKER);
		file->pathname = NULL;
	}
	kobj_delete((kobj_t) file, M_LINKER);
	return (0);
}

int linker_ctf_get(linker_file_t file, linker_ctf_t *lc)
{
	return (LINKER_CTF_GET(file, lc));
}

static int linker_file_add_dependency(linker_file_t file, linker_file_t dep)
{
	linker_file_t *newdeps;

	sx_assert(&kld_sx, SA_XLOCKED);
	file->deps = realloc(file->deps, (file->ndeps + 1) * sizeof(*newdeps), M_LINKER, M_WAITOK | M_ZERO);
	file->deps[file->ndeps] = dep;
	file->ndeps++;
	KLD_DPF(FILE, ("linker_file_add_dependency:" " adding %s as dependency for %s\n", dep->filename, file->filename));

	return (0);
}


int linker_file_lookup_set(linker_file_t file, const char *name, void *firstp, void *lastp, int *countp)

{

	sx_assert(&kld_sx, SA_LOCKED);
	return (LINKER_LOOKUP_SET(file, name, firstp, lastp, countp));
}


int linker_file_function_listall(linker_file_t lf, linker_function_nameval_callback_t callback_func, void *arg)

{
	return (LINKER_EACH_FUNCTION_NAMEVAL(lf, callback_func, arg));
}

caddr_t linker_file_lookup_symbol(linker_file_t file, const char *name, int deps)
{
	caddr_t sym;
	int locked;

	locked = sx_xlocked(&kld_sx);
	if (!locked)
		sx_xlock(&kld_sx);
	sym = linker_file_lookup_symbol_internal(file, name, deps);
	if (!locked)
		sx_xunlock(&kld_sx);
	return (sym);
}

static caddr_t linker_file_lookup_symbol_internal(linker_file_t file, const char *name, int deps)

{
	c_linker_sym_t sym;
	linker_symval_t symval;
	caddr_t address;
	size_t common_size = 0;
	int i;

	sx_assert(&kld_sx, SA_XLOCKED);
	KLD_DPF(SYM, ("linker_file_lookup_symbol: file=%p, name=%s, deps=%d\n", file, name, deps));

	if (LINKER_LOOKUP_SYMBOL(file, name, &sym) == 0) {
		LINKER_SYMBOL_VALUES(file, sym, &symval);
		if (symval.value == 0)
			
			common_size = symval.size;
		else {
			KLD_DPF(SYM, ("linker_file_lookup_symbol: symbol" ".value=%p\n", symval.value));
			return (symval.value);
		}
	}
	if (deps) {
		for (i = 0; i < file->ndeps; i++) {
			address = linker_file_lookup_symbol_internal( file->deps[i], name, 0);
			if (address) {
				KLD_DPF(SYM, ("linker_file_lookup_symbol:" " deps value=%p\n", address));
				return (address);
			}
		}
	}
	if (common_size > 0) {
		
		struct common_symbol *cp;

		STAILQ_FOREACH(cp, &file->common, link) {
			if (strcmp(cp->name, name) == 0) {
				KLD_DPF(SYM, ("linker_file_lookup_symbol:" " old common value=%p\n", cp->address));
				return (cp->address);
			}
		}
		
		common_size = (common_size + sizeof(int) - 1) & -sizeof(int);
		cp = malloc(sizeof(struct common_symbol)
		    + common_size + strlen(name) + 1, M_LINKER, M_WAITOK | M_ZERO);
		cp->address = (caddr_t)(cp + 1);
		cp->name = cp->address + common_size;
		strcpy(cp->name, name);
		bzero(cp->address, common_size);
		STAILQ_INSERT_TAIL(&file->common, cp, link);

		KLD_DPF(SYM, ("linker_file_lookup_symbol: new common" " value=%p\n", cp->address));
		return (cp->address);
	}
	KLD_DPF(SYM, ("linker_file_lookup_symbol: fail\n"));
	return (0);
}



static int linker_debug_lookup(const char *symstr, c_linker_sym_t *sym)
{
	linker_file_t lf;

	TAILQ_FOREACH(lf, &linker_files, link) {
		if (LINKER_LOOKUP_SYMBOL(lf, symstr, sym) == 0)
			return (0);
	}
	return (ENOENT);
}


static int linker_debug_search_symbol(caddr_t value, c_linker_sym_t *sym, long *diffp)
{
	linker_file_t lf;
	c_linker_sym_t best, es;
	u_long diff, bestdiff, off;

	best = 0;
	off = (uintptr_t)value;
	bestdiff = off;
	TAILQ_FOREACH(lf, &linker_files, link) {
		if (LINKER_SEARCH_SYMBOL(lf, value, &es, &diff) != 0)
			continue;
		if (es != 0 && diff < bestdiff) {
			best = es;
			bestdiff = diff;
		}
		if (bestdiff == 0)
			break;
	}
	if (best) {
		*sym = best;
		*diffp = bestdiff;
		return (0);
	} else {
		*sym = 0;
		*diffp = off;
		return (ENOENT);
	}
}

static int linker_debug_symbol_values(c_linker_sym_t sym, linker_symval_t *symval)
{
	linker_file_t lf;

	TAILQ_FOREACH(lf, &linker_files, link) {
		if (LINKER_SYMBOL_VALUES(lf, sym, symval) == 0)
			return (0);
	}
	return (ENOENT);
}

static int linker_debug_search_symbol_name(caddr_t value, char *buf, u_int buflen, long *offset)

{
	linker_symval_t symval;
	c_linker_sym_t sym;
	int error;

	*offset = 0;
	error = linker_debug_search_symbol(value, &sym, offset);
	if (error)
		return (error);
	error = linker_debug_symbol_values(sym, &symval);
	if (error)
		return (error);
	strlcpy(buf, symval.name, buflen);
	return (0);
}



int linker_ddb_lookup(const char *symstr, c_linker_sym_t *sym)
{

	return (linker_debug_lookup(symstr, sym));
}


int linker_ddb_search_symbol(caddr_t value, c_linker_sym_t *sym, long *diffp)
{

	return (linker_debug_search_symbol(value, sym, diffp));
}

int linker_ddb_symbol_values(c_linker_sym_t sym, linker_symval_t *symval)
{

	return (linker_debug_symbol_values(sym, symval));
}

int linker_ddb_search_symbol_name(caddr_t value, char *buf, u_int buflen, long *offset)

{

	return (linker_debug_search_symbol_name(value, buf, buflen, offset));
}


int linker_search_symbol_name(caddr_t value, char *buf, u_int buflen, long *offset)

{
	int error;

	sx_slock(&kld_sx);
	error = linker_debug_search_symbol_name(value, buf, buflen, offset);
	sx_sunlock(&kld_sx);
	return (error);
}


int kern_kldload(struct thread *td, const char *file, int *fileid)
{
	const char *kldname, *modname;
	linker_file_t lf;
	int error;

	if ((error = securelevel_gt(td->td_ucred, 0)) != 0)
		return (error);

	if ((error = priv_check(td, PRIV_KLD_LOAD)) != 0)
		return (error);

	
	CURVNET_SET(TD_TO_VNET(td));

	
	if (strchr(file, '/') || strchr(file, '.')) {
		kldname = file;
		modname = NULL;
	} else {
		kldname = NULL;
		modname = file;
	}

	sx_xlock(&kld_sx);
	error = linker_load_module(kldname, modname, NULL, NULL, &lf);
	if (error) {
		sx_xunlock(&kld_sx);
		goto done;
	}
	lf->userrefs++;
	if (fileid != NULL)
		*fileid = lf->id;
	sx_xunlock(&kld_sx);

done:
	CURVNET_RESTORE();
	return (error);
}

int sys_kldload(struct thread *td, struct kldload_args *uap)
{
	char *pathname = NULL;
	int error, fileid;

	td->td_retval[0] = -1;

	pathname = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	error = copyinstr(uap->file, pathname, MAXPATHLEN, NULL);
	if (error == 0) {
		error = kern_kldload(td, pathname, &fileid);
		if (error == 0)
			td->td_retval[0] = fileid;
	}
	free(pathname, M_TEMP);
	return (error);
}

int kern_kldunload(struct thread *td, int fileid, int flags)
{
	linker_file_t lf;
	int error = 0;

	if ((error = securelevel_gt(td->td_ucred, 0)) != 0)
		return (error);

	if ((error = priv_check(td, PRIV_KLD_UNLOAD)) != 0)
		return (error);

	CURVNET_SET(TD_TO_VNET(td));
	sx_xlock(&kld_sx);
	lf = linker_find_file_by_id(fileid);
	if (lf) {
		KLD_DPF(FILE, ("kldunload: lf->userrefs=%d\n", lf->userrefs));

		if (lf->userrefs == 0) {
			
			printf("kldunload: attempt to unload file that was" " loaded by the kernel\n");
			error = EBUSY;
		} else {
			lf->userrefs--;
			error = linker_file_unload(lf, flags);
			if (error)
				lf->userrefs++;
		}
	} else error = ENOENT;
	sx_xunlock(&kld_sx);

	CURVNET_RESTORE();
	return (error);
}

int sys_kldunload(struct thread *td, struct kldunload_args *uap)
{

	return (kern_kldunload(td, uap->fileid, LINKER_UNLOAD_NORMAL));
}

int sys_kldunloadf(struct thread *td, struct kldunloadf_args *uap)
{

	if (uap->flags != LINKER_UNLOAD_NORMAL && uap->flags != LINKER_UNLOAD_FORCE)
		return (EINVAL);
	return (kern_kldunload(td, uap->fileid, uap->flags));
}

int sys_kldfind(struct thread *td, struct kldfind_args *uap)
{
	char *pathname;
	const char *filename;
	linker_file_t lf;
	int error;


	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);


	td->td_retval[0] = -1;

	pathname = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	if ((error = copyinstr(uap->file, pathname, MAXPATHLEN, NULL)) != 0)
		goto out;

	filename = linker_basename(pathname);
	sx_xlock(&kld_sx);
	lf = linker_find_file_by_name(filename);
	if (lf)
		td->td_retval[0] = lf->id;
	else error = ENOENT;
	sx_xunlock(&kld_sx);
out:
	free(pathname, M_TEMP);
	return (error);
}

int sys_kldnext(struct thread *td, struct kldnext_args *uap)
{
	linker_file_t lf;
	int error = 0;


	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);


	sx_xlock(&kld_sx);
	if (uap->fileid == 0)
		lf = TAILQ_FIRST(&linker_files);
	else {
		lf = linker_find_file_by_id(uap->fileid);
		if (lf == NULL) {
			error = ENOENT;
			goto out;
		}
		lf = TAILQ_NEXT(lf, link);
	}

	
	while (lf != NULL && !(lf->flags & LINKER_FILE_LINKED))
		lf = TAILQ_NEXT(lf, link);

	if (lf)
		td->td_retval[0] = lf->id;
	else td->td_retval[0] = 0;
out:
	sx_xunlock(&kld_sx);
	return (error);
}

int sys_kldstat(struct thread *td, struct kldstat_args *uap)
{
	struct kld_file_stat stat;
	int error, version;

	
	if ((error = copyin(&uap->stat->version, &version, sizeof(version)))
	    != 0)
		return (error);
	if (version != sizeof(struct kld_file_stat_1) && version != sizeof(struct kld_file_stat))
		return (EINVAL);

	error = kern_kldstat(td, uap->fileid, &stat);
	if (error != 0)
		return (error);
	return (copyout(&stat, uap->stat, version));
}

int kern_kldstat(struct thread *td, int fileid, struct kld_file_stat *stat)
{
	linker_file_t lf;
	int namelen;

	int error;

	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);


	sx_xlock(&kld_sx);
	lf = linker_find_file_by_id(fileid);
	if (lf == NULL) {
		sx_xunlock(&kld_sx);
		return (ENOENT);
	}

	
	namelen = strlen(lf->filename) + 1;
	if (namelen > sizeof(stat->name))
		namelen = sizeof(stat->name);
	bcopy(lf->filename, &stat->name[0], namelen);
	stat->refs = lf->refs;
	stat->id = lf->id;
	stat->address = lf->address;
	stat->size = lf->size;
	
	namelen = strlen(lf->pathname) + 1;
	if (namelen > sizeof(stat->pathname))
		namelen = sizeof(stat->pathname);
	bcopy(lf->pathname, &stat->pathname[0], namelen);
	sx_xunlock(&kld_sx);

	td->td_retval[0] = 0;
	return (0);
}


DB_COMMAND(kldstat, db_kldstat)
{
	linker_file_t lf;


	db_printf("Id Refs Address%*c Size     Name\n", POINTER_WIDTH - 7, ' ');

	TAILQ_FOREACH(lf, &linker_files, link) {
		if (db_pager_quit)
			return;
		db_printf("%2d %4d %p %-8zx %s\n", lf->id, lf->refs, lf->address, lf->size, lf->filename);
	}
}


int sys_kldfirstmod(struct thread *td, struct kldfirstmod_args *uap)
{
	linker_file_t lf;
	module_t mp;
	int error = 0;


	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);


	sx_xlock(&kld_sx);
	lf = linker_find_file_by_id(uap->fileid);
	if (lf) {
		MOD_SLOCK;
		mp = TAILQ_FIRST(&lf->modules);
		if (mp != NULL)
			td->td_retval[0] = module_getid(mp);
		else td->td_retval[0] = 0;
		MOD_SUNLOCK;
	} else error = ENOENT;
	sx_xunlock(&kld_sx);
	return (error);
}

int sys_kldsym(struct thread *td, struct kldsym_args *uap)
{
	char *symstr = NULL;
	c_linker_sym_t sym;
	linker_symval_t symval;
	linker_file_t lf;
	struct kld_sym_lookup lookup;
	int error = 0;


	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);


	if ((error = copyin(uap->data, &lookup, sizeof(lookup))) != 0)
		return (error);
	if (lookup.version != sizeof(lookup) || uap->cmd != KLDSYM_LOOKUP)
		return (EINVAL);
	symstr = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	if ((error = copyinstr(lookup.symname, symstr, MAXPATHLEN, NULL)) != 0)
		goto out;
	sx_xlock(&kld_sx);
	if (uap->fileid != 0) {
		lf = linker_find_file_by_id(uap->fileid);
		if (lf == NULL)
			error = ENOENT;
		else if (LINKER_LOOKUP_SYMBOL(lf, symstr, &sym) == 0 && LINKER_SYMBOL_VALUES(lf, sym, &symval) == 0) {
			lookup.symvalue = (uintptr_t) symval.value;
			lookup.symsize = symval.size;
			error = copyout(&lookup, uap->data, sizeof(lookup));
		} else error = ENOENT;
	} else {
		TAILQ_FOREACH(lf, &linker_files, link) {
			if (LINKER_LOOKUP_SYMBOL(lf, symstr, &sym) == 0 && LINKER_SYMBOL_VALUES(lf, sym, &symval) == 0) {
				lookup.symvalue = (uintptr_t)symval.value;
				lookup.symsize = symval.size;
				error = copyout(&lookup, uap->data, sizeof(lookup));
				break;
			}
		}
		if (lf == NULL)
			error = ENOENT;
	}
	sx_xunlock(&kld_sx);
out:
	free(symstr, M_TEMP);
	return (error);
}



static modlist_t modlist_lookup(const char *name, int ver)
{
	modlist_t mod;

	TAILQ_FOREACH(mod, &found_modules, link) {
		if (strcmp(mod->name, name) == 0 && (ver == 0 || mod->version == ver))
			return (mod);
	}
	return (NULL);
}

static modlist_t modlist_lookup2(const char *name, const struct mod_depend *verinfo)
{
	modlist_t mod, bestmod;
	int ver;

	if (verinfo == NULL)
		return (modlist_lookup(name, 0));
	bestmod = NULL;
	TAILQ_FOREACH(mod, &found_modules, link) {
		if (strcmp(mod->name, name) != 0)
			continue;
		ver = mod->version;
		if (ver == verinfo->md_ver_preferred)
			return (mod);
		if (ver >= verinfo->md_ver_minimum && ver <= verinfo->md_ver_maximum && (bestmod == NULL || ver > bestmod->version))

			bestmod = mod;
	}
	return (bestmod);
}

static modlist_t modlist_newmodule(const char *modname, int version, linker_file_t container)
{
	modlist_t mod;

	mod = malloc(sizeof(struct modlist), M_LINKER, M_NOWAIT | M_ZERO);
	if (mod == NULL)
		panic("no memory for module list");
	mod->container = container;
	mod->name = modname;
	mod->version = version;
	TAILQ_INSERT_TAIL(&found_modules, mod, link);
	return (mod);
}

static void linker_addmodules(linker_file_t lf, struct mod_metadata **start, struct mod_metadata **stop, int preload)

{
	struct mod_metadata *mp, **mdp;
	const char *modname;
	int ver;

	for (mdp = start; mdp < stop; mdp++) {
		mp = *mdp;
		if (mp->md_type != MDT_VERSION)
			continue;
		modname = mp->md_cval;
		ver = ((const struct mod_version *)mp->md_data)->mv_version;
		if (modlist_lookup(modname, ver) != NULL) {
			printf("module %s already present!\n", modname);
			
			continue;
		}
		modlist_newmodule(modname, ver, lf);
	}
}

static void linker_preload(void *arg)
{
	caddr_t modptr;
	const char *modname, *nmodname;
	char *modtype;
	linker_file_t lf, nlf;
	linker_class_t lc;
	int error;
	linker_file_list_t loaded_files;
	linker_file_list_t depended_files;
	struct mod_metadata *mp, *nmp;
	struct mod_metadata **start, **stop, **mdp, **nmdp;
	const struct mod_depend *verinfo;
	int nver;
	int resolves;
	modlist_t mod;
	struct sysinit **si_start, **si_stop;

	TAILQ_INIT(&loaded_files);
	TAILQ_INIT(&depended_files);
	TAILQ_INIT(&found_modules);
	error = 0;

	modptr = NULL;
	sx_xlock(&kld_sx);
	while ((modptr = preload_search_next_name(modptr)) != NULL) {
		modname = (char *)preload_search_info(modptr, MODINFO_NAME);
		modtype = (char *)preload_search_info(modptr, MODINFO_TYPE);
		if (modname == NULL) {
			printf("Preloaded module at %p does not have a" " name!\n", modptr);
			continue;
		}
		if (modtype == NULL) {
			printf("Preloaded module at %p does not have a type!\n", modptr);
			continue;
		}
		if (bootverbose)
			printf("Preloaded %s \"%s\" at %p.\n", modtype, modname, modptr);
		lf = NULL;
		TAILQ_FOREACH(lc, &classes, link) {
			error = LINKER_LINK_PRELOAD(lc, modname, &lf);
			if (!error)
				break;
			lf = NULL;
		}
		if (lf)
			TAILQ_INSERT_TAIL(&loaded_files, lf, loaded);
	}

	
	if (linker_file_lookup_set(linker_kernel_file, MDT_SETNAME, &start, &stop, NULL) == 0)
		linker_addmodules(linker_kernel_file, start, stop, 1);

	
restart:
	TAILQ_FOREACH(lf, &loaded_files, loaded) {
		error = linker_file_lookup_set(lf, MDT_SETNAME, &start, &stop, NULL);
		
		resolves = 1;	
		if (!error) {
			for (mdp = start; mdp < stop; mdp++) {
				mp = *mdp;
				if (mp->md_type != MDT_DEPEND)
					continue;
				modname = mp->md_cval;
				verinfo = mp->md_data;
				for (nmdp = start; nmdp < stop; nmdp++) {
					nmp = *nmdp;
					if (nmp->md_type != MDT_VERSION)
						continue;
					nmodname = nmp->md_cval;
					if (strcmp(modname, nmodname) == 0)
						break;
				}
				if (nmdp < stop)   
					continue;

				
				if (modlist_lookup2(modname, verinfo) == NULL)
					resolves = 0;
			}
		}
		
		if (resolves) {
			if (!error) {
				for (mdp = start; mdp < stop; mdp++) {
					mp = *mdp;
					if (mp->md_type != MDT_VERSION)
						continue;
					modname = mp->md_cval;
					nver = ((const struct mod_version *)
					    mp->md_data)->mv_version;
					if (modlist_lookup(modname, nver) != NULL) {
						printf("module %s already" " present!\n", modname);
						TAILQ_REMOVE(&loaded_files, lf, loaded);
						linker_file_unload(lf, LINKER_UNLOAD_FORCE);
						
						goto restart;
					}
					modlist_newmodule(modname, nver, lf);
				}
			}
			TAILQ_REMOVE(&loaded_files, lf, loaded);
			TAILQ_INSERT_TAIL(&depended_files, lf, loaded);
			
			goto restart;
		}
	}

	
	while ((lf = TAILQ_FIRST(&loaded_files)) != NULL) {
		TAILQ_REMOVE(&loaded_files, lf, loaded);
		printf("KLD file %s is missing dependencies\n", lf->filename);
		linker_file_unload(lf, LINKER_UNLOAD_FORCE);
	}

	
	TAILQ_FOREACH_SAFE(lf, &depended_files, loaded, nlf) {
		if (linker_kernel_file) {
			linker_kernel_file->refs++;
			error = linker_file_add_dependency(lf, linker_kernel_file);
			if (error)
				panic("cannot add dependency");
		}
		error = linker_file_lookup_set(lf, MDT_SETNAME, &start, &stop, NULL);
		if (!error) {
			for (mdp = start; mdp < stop; mdp++) {
				mp = *mdp;
				if (mp->md_type != MDT_DEPEND)
					continue;
				modname = mp->md_cval;
				verinfo = mp->md_data;
				mod = modlist_lookup2(modname, verinfo);
				if (mod == NULL) {
					printf("KLD file %s - cannot find " "dependency \"%s\"\n", lf->filename, modname);

					goto fail;
				}
				
				if (lf == mod->container)
					continue;
				mod->container->refs++;
				error = linker_file_add_dependency(lf, mod->container);
				if (error)
					panic("cannot add dependency");
			}
		}
		
		error = LINKER_LINK_PRELOAD_FINISH(lf);
		if (error) {
			printf("KLD file %s - could not finalize loading\n", lf->filename);
			goto fail;
		}
		linker_file_register_modules(lf);
		if (!TAILQ_EMPTY(&lf->modules))
			lf->flags |= LINKER_FILE_MODULES;
		if (linker_file_lookup_set(lf, "sysinit_set", &si_start, &si_stop, NULL) == 0)
			sysinit_add(si_start, si_stop);
		linker_file_register_sysctls(lf, true);
		lf->flags |= LINKER_FILE_LINKED;
		continue;
fail:
		TAILQ_REMOVE(&depended_files, lf, loaded);
		linker_file_unload(lf, LINKER_UNLOAD_FORCE);
	}
	sx_xunlock(&kld_sx);
	
}

SYSINIT(preload, SI_SUB_KLD, SI_ORDER_MIDDLE, linker_preload, 0);


static void linker_preload_finish(void *arg)
{
	linker_file_t lf, nlf;

	sx_xlock(&kld_sx);
	TAILQ_FOREACH_SAFE(lf, &linker_files, link, nlf) {
		
		if ((lf->flags & LINKER_FILE_MODULES) != 0 && TAILQ_EMPTY(&lf->modules)) {
			linker_file_unload(lf, LINKER_UNLOAD_FORCE);
			continue;
		}

		lf->flags &= ~LINKER_FILE_MODULES;
		lf->userrefs++;	
	}
	sx_xunlock(&kld_sx);
}


SYSINIT(preload_finish, SI_SUB_KTHREAD_INIT - 100, SI_ORDER_MIDDLE, linker_preload_finish, 0);



static char linker_hintfile[] = "linker.hints";
static char linker_path[MAXPATHLEN] = "/boot/kernel;/boot/modules";

SYSCTL_STRING(_kern, OID_AUTO, module_path, CTLFLAG_RWTUN, linker_path, sizeof(linker_path), "module load search path");

TUNABLE_STR("module_path", linker_path, sizeof(linker_path));

static char *linker_ext_list[] = {
	"", ".ko", NULL };




static char * linker_lookup_file(const char *path, int pathlen, const char *name, int namelen, struct vattr *vap)

{
	struct nameidata nd;
	struct thread *td = curthread;	
	char *result, **cpp, *sep;
	int error, len, extlen, reclen, flags;
	enum vtype type;

	extlen = 0;
	for (cpp = linker_ext_list; *cpp; cpp++) {
		len = strlen(*cpp);
		if (len > extlen)
			extlen = len;
	}
	extlen++;		
	sep = (path[pathlen - 1] != '/') ? "/" : "";

	reclen = pathlen + strlen(sep) + namelen + extlen + 1;
	result = malloc(reclen, M_LINKER, M_WAITOK);
	for (cpp = linker_ext_list; *cpp; cpp++) {
		snprintf(result, reclen, "%.*s%s%.*s%s", pathlen, path, sep, namelen, name, *cpp);
		
		NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, result, td);
		flags = FREAD;
		error = vn_open(&nd, &flags, 0, NULL);
		if (error == 0) {
			NDFREE(&nd, NDF_ONLY_PNBUF);
			type = nd.ni_vp->v_type;
			if (vap)
				VOP_GETATTR(nd.ni_vp, vap, td->td_ucred);
			VOP_UNLOCK(nd.ni_vp, 0);
			vn_close(nd.ni_vp, FREAD, td->td_ucred, td);
			if (type == VREG)
				return (result);
		}
	}
	free(result, M_LINKER);
	return (NULL);
}




static char * linker_hints_lookup(const char *path, int pathlen, const char *modname, int modnamelen, const struct mod_depend *verinfo)

{
	struct thread *td = curthread;	
	struct ucred *cred = td ? td->td_ucred : NULL;
	struct nameidata nd;
	struct vattr vattr, mattr;
	u_char *hints = NULL;
	u_char *cp, *recptr, *bufend, *result, *best, *pathbuf, *sep;
	int error, ival, bestver, *intp, found, flags, clen, blen;
	ssize_t reclen;

	result = NULL;
	bestver = found = 0;

	sep = (path[pathlen - 1] != '/') ? "/" : "";
	reclen = imax(modnamelen, strlen(linker_hintfile)) + pathlen + strlen(sep) + 1;
	pathbuf = malloc(reclen, M_LINKER, M_WAITOK);
	snprintf(pathbuf, reclen, "%.*s%s%s", pathlen, path, sep, linker_hintfile);

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, pathbuf, td);
	flags = FREAD;
	error = vn_open(&nd, &flags, 0, NULL);
	if (error)
		goto bad;
	NDFREE(&nd, NDF_ONLY_PNBUF);
	if (nd.ni_vp->v_type != VREG)
		goto bad;
	best = cp = NULL;
	error = VOP_GETATTR(nd.ni_vp, &vattr, cred);
	if (error)
		goto bad;
	
	if (vattr.va_size > LINKER_HINTS_MAX) {
		printf("hints file too large %ld\n", (long)vattr.va_size);
		goto bad;
	}
	hints = malloc(vattr.va_size, M_TEMP, M_WAITOK);
	error = vn_rdwr(UIO_READ, nd.ni_vp, (caddr_t)hints, vattr.va_size, 0, UIO_SYSSPACE, IO_NODELOCKED, cred, NOCRED, &reclen, td);
	if (error)
		goto bad;
	VOP_UNLOCK(nd.ni_vp, 0);
	vn_close(nd.ni_vp, FREAD, cred, td);
	nd.ni_vp = NULL;
	if (reclen != 0) {
		printf("can't read %zd\n", reclen);
		goto bad;
	}
	intp = (int *)hints;
	ival = *intp++;
	if (ival != LINKER_HINTS_VERSION) {
		printf("hints file version mismatch %d\n", ival);
		goto bad;
	}
	bufend = hints + vattr.va_size;
	recptr = (u_char *)intp;
	clen = blen = 0;
	while (recptr < bufend && !found) {
		intp = (int *)recptr;
		reclen = *intp++;
		ival = *intp++;
		cp = (char *)intp;
		switch (ival) {
		case MDT_VERSION:
			clen = *cp++;
			if (clen != modnamelen || bcmp(cp, modname, clen) != 0)
				break;
			cp += clen;
			INT_ALIGN(hints, cp);
			ival = *(int *)cp;
			cp += sizeof(int);
			clen = *cp++;
			if (verinfo == NULL || ival == verinfo->md_ver_preferred) {
				found = 1;
				break;
			}
			if (ival >= verinfo->md_ver_minimum && ival <= verinfo->md_ver_maximum && ival > bestver) {

				bestver = ival;
				best = cp;
				blen = clen;
			}
			break;
		default:
			break;
		}
		recptr += reclen + sizeof(int);
	}
	
	if (found)
		result = linker_lookup_file(path, pathlen, cp, clen, &mattr);
	else if (best)
		result = linker_lookup_file(path, pathlen, best, blen, &mattr);

	
	if (result && timespeccmp(&mattr.va_mtime, &vattr.va_mtime, >))
		printf("warning: KLD '%s' is newer than the linker.hints" " file\n", result);
bad:
	free(pathbuf, M_LINKER);
	if (hints)
		free(hints, M_TEMP);
	if (nd.ni_vp != NULL) {
		VOP_UNLOCK(nd.ni_vp, 0);
		vn_close(nd.ni_vp, FREAD, cred, td);
	}
	
	if (!found && !bestver && result == NULL)
		result = linker_lookup_file(path, pathlen, modname, modnamelen, NULL);
	return (result);
}


static char * linker_search_module(const char *modname, int modnamelen, const struct mod_depend *verinfo)

{
	char *cp, *ep, *result;

	
	for (cp = linker_path; *cp; cp = ep + 1) {
		
		for (ep = cp; (*ep != 0) && (*ep != ';'); ep++);
		result = linker_hints_lookup(cp, ep - cp, modname, modnamelen, verinfo);
		if (result != NULL)
			return (result);
		if (*ep == 0)
			break;
	}
	return (NULL);
}


static char * linker_search_kld(const char *name)
{
	char *cp, *ep, *result;
	int len;

	
	if (strchr(name, '/'))
		return (strdup(name, M_LINKER));

	
	len = strlen(name);
	for (ep = linker_path; *ep; ep++) {
		cp = ep;
		
		for (; *ep != 0 && *ep != ';'; ep++);
		result = linker_lookup_file(cp, ep - cp, name, len, NULL);
		if (result != NULL)
			return (result);
	}
	return (NULL);
}

static const char * linker_basename(const char *path)
{
	const char *filename;

	filename = strrchr(path, '/');
	if (filename == NULL)
		return path;
	if (filename[1])
		filename++;
	return (filename);
}



void * linker_hwpmc_list_objects(void)
{
	linker_file_t lf;
	struct pmckern_map_in *kobase;
	int i, nmappings;

	nmappings = 0;
	sx_slock(&kld_sx);
	TAILQ_FOREACH(lf, &linker_files, link)
		nmappings++;

	
	kobase = malloc((nmappings + 1) * sizeof(struct pmckern_map_in), M_LINKER, M_WAITOK | M_ZERO);
	i = 0;
	TAILQ_FOREACH(lf, &linker_files, link) {

		
		kobase[i].pm_file = lf->filename;
		kobase[i].pm_address = (uintptr_t)lf->address;
		i++;
	}
	sx_sunlock(&kld_sx);

	KASSERT(i > 0, ("linker_hpwmc_list_objects: no kernel objects?"));

	
	KASSERT(kobase[i].pm_file == NULL, ("linker_hwpmc_list_objects: last object not NULL"));

	return ((void *)kobase);
}



static int linker_load_module(const char *kldname, const char *modname, struct linker_file *parent, const struct mod_depend *verinfo, struct linker_file **lfpp)


{
	linker_file_t lfdep;
	const char *filename;
	char *pathname;
	int error;

	sx_assert(&kld_sx, SA_XLOCKED);
	if (modname == NULL) {
		
		KASSERT(verinfo == NULL, ("linker_load_module: verinfo" " is not NULL"));
		pathname = linker_search_kld(kldname);
	} else {
		if (modlist_lookup2(modname, verinfo) != NULL)
			return (EEXIST);
		if (kldname != NULL)
			pathname = strdup(kldname, M_LINKER);
		else if (rootvnode == NULL)
			pathname = NULL;
		else  pathname = linker_search_module(modname, strlen(modname), verinfo);


	}
	if (pathname == NULL)
		return (ENOENT);

	
	filename = linker_basename(pathname);
	if (linker_find_file_by_name(filename))
		error = EEXIST;
	else do {
		error = linker_load_file(pathname, &lfdep);
		if (error)
			break;
		if (modname && verinfo && modlist_lookup2(modname, verinfo) == NULL) {
			linker_file_unload(lfdep, LINKER_UNLOAD_FORCE);
			error = ENOENT;
			break;
		}
		if (parent) {
			error = linker_file_add_dependency(parent, lfdep);
			if (error)
				break;
		}
		if (lfpp)
			*lfpp = lfdep;
	} while (0);
	free(pathname, M_LINKER);
	return (error);
}


int linker_load_dependencies(linker_file_t lf)
{
	linker_file_t lfdep;
	struct mod_metadata **start, **stop, **mdp, **nmdp;
	struct mod_metadata *mp, *nmp;
	const struct mod_depend *verinfo;
	modlist_t mod;
	const char *modname, *nmodname;
	int ver, error = 0, count;

	
	sx_assert(&kld_sx, SA_XLOCKED);
	if (linker_kernel_file) {
		linker_kernel_file->refs++;
		error = linker_file_add_dependency(lf, linker_kernel_file);
		if (error)
			return (error);
	}
	if (linker_file_lookup_set(lf, MDT_SETNAME, &start, &stop, &count) != 0)
		return (0);
	for (mdp = start; mdp < stop; mdp++) {
		mp = *mdp;
		if (mp->md_type != MDT_VERSION)
			continue;
		modname = mp->md_cval;
		ver = ((const struct mod_version *)mp->md_data)->mv_version;
		mod = modlist_lookup(modname, ver);
		if (mod != NULL) {
			printf("interface %s.%d already present in the KLD" " '%s'!\n", modname, ver, mod->container->filename);

			return (EEXIST);
		}
	}

	for (mdp = start; mdp < stop; mdp++) {
		mp = *mdp;
		if (mp->md_type != MDT_DEPEND)
			continue;
		modname = mp->md_cval;
		verinfo = mp->md_data;
		nmodname = NULL;
		for (nmdp = start; nmdp < stop; nmdp++) {
			nmp = *nmdp;
			if (nmp->md_type != MDT_VERSION)
				continue;
			nmodname = nmp->md_cval;
			if (strcmp(modname, nmodname) == 0)
				break;
		}
		if (nmdp < stop)
			continue;
		mod = modlist_lookup2(modname, verinfo);
		if (mod) {	
			lfdep = mod->container;
			lfdep->refs++;
			error = linker_file_add_dependency(lf, lfdep);
			if (error)
				break;
			continue;
		}
		error = linker_load_module(NULL, modname, lf, verinfo, NULL);
		if (error) {
			printf("KLD %s: depends on %s - not available or" " version mismatch\n", lf->filename, modname);
			break;
		}
	}

	if (error)
		return (error);
	linker_addmodules(lf, start, stop, 0);
	return (error);
}

static int sysctl_kern_function_list_iterate(const char *name, void *opaque)
{
	struct sysctl_req *req;

	req = opaque;
	return (SYSCTL_OUT(req, name, strlen(name) + 1));
}


static int sysctl_kern_function_list(SYSCTL_HANDLER_ARGS)
{
	linker_file_t lf;
	int error;


	error = mac_kld_check_stat(req->td->td_ucred);
	if (error)
		return (error);

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	sx_xlock(&kld_sx);
	TAILQ_FOREACH(lf, &linker_files, link) {
		error = LINKER_EACH_FUNCTION_NAME(lf, sysctl_kern_function_list_iterate, req);
		if (error) {
			sx_xunlock(&kld_sx);
			return (error);
		}
	}
	sx_xunlock(&kld_sx);
	return (SYSCTL_OUT(req, "", 1));
}

SYSCTL_PROC(_kern, OID_AUTO, function_list, CTLTYPE_OPAQUE | CTLFLAG_RD, NULL, 0, sysctl_kern_function_list, "", "kernel function list");
