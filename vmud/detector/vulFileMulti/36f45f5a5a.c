





















static int config_fetch_recurse_submodules = RECURSE_SUBMODULES_ON_DEMAND;
static int config_update_recurse_submodules = RECURSE_SUBMODULES_OFF;
static int parallel_jobs = 1;
static struct string_list changed_submodule_paths = STRING_LIST_INIT_DUP;
static int initialized_fetch_ref_tips;
static struct oid_array ref_tips_before_fetch;
static struct oid_array ref_tips_after_fetch;


static int gitmodules_is_unmerged;


static int gitmodules_is_modified;

int is_staging_gitmodules_ok(void)
{
	return !gitmodules_is_modified;
}


int update_path_in_gitmodules(const char *oldpath, const char *newpath)
{
	struct strbuf entry = STRBUF_INIT;
	const struct submodule *submodule;

	if (!file_exists(".gitmodules")) 
		return -1;

	if (gitmodules_is_unmerged)
		die(_("Cannot change unmerged .gitmodules, resolve merge conflicts first"));

	submodule = submodule_from_path(null_sha1, oldpath);
	if (!submodule || !submodule->name) {
		warning(_("Could not find section in .gitmodules where path=%s"), oldpath);
		return -1;
	}
	strbuf_addstr(&entry, "submodule.");
	strbuf_addstr(&entry, submodule->name);
	strbuf_addstr(&entry, ".path");
	if (git_config_set_in_file_gently(".gitmodules", entry.buf, newpath) < 0) {
		
		warning(_("Could not update .gitmodules entry %s"), entry.buf);
		strbuf_release(&entry);
		return -1;
	}
	strbuf_release(&entry);
	return 0;
}


int remove_path_from_gitmodules(const char *path)
{
	struct strbuf sect = STRBUF_INIT;
	const struct submodule *submodule;

	if (!file_exists(".gitmodules")) 
		return -1;

	if (gitmodules_is_unmerged)
		die(_("Cannot change unmerged .gitmodules, resolve merge conflicts first"));

	submodule = submodule_from_path(null_sha1, path);
	if (!submodule || !submodule->name) {
		warning(_("Could not find section in .gitmodules where path=%s"), path);
		return -1;
	}
	strbuf_addstr(&sect, "submodule.");
	strbuf_addstr(&sect, submodule->name);
	if (git_config_rename_section_in_file(".gitmodules", sect.buf, NULL) < 0) {
		
		warning(_("Could not remove .gitmodules entry for %s"), path);
		strbuf_release(&sect);
		return -1;
	}
	strbuf_release(&sect);
	return 0;
}

void stage_updated_gitmodules(void)
{
	if (add_file_to_cache(".gitmodules", 0))
		die(_("staging updated .gitmodules failed"));
}

static int add_submodule_odb(const char *path)
{
	struct strbuf objects_directory = STRBUF_INIT;
	int ret = 0;

	ret = strbuf_git_path_submodule(&objects_directory, path, "objects/");
	if (ret)
		goto done;
	if (!is_directory(objects_directory.buf)) {
		ret = -1;
		goto done;
	}
	add_to_alternates_memory(objects_directory.buf);
done:
	strbuf_release(&objects_directory);
	return ret;
}

void set_diffopt_flags_from_submodule_config(struct diff_options *diffopt, const char *path)
{
	const struct submodule *submodule = submodule_from_path(null_sha1, path);
	if (submodule) {
		if (submodule->ignore)
			handle_ignore_submodules_arg(diffopt, submodule->ignore);
		else if (gitmodules_is_unmerged)
			DIFF_OPT_SET(diffopt, IGNORE_SUBMODULES);
	}
}


static int git_modules_config(const char *var, const char *value, void *cb)
{
	if (!strcmp(var, "submodule.fetchjobs")) {
		parallel_jobs = git_config_int(var, value);
		if (parallel_jobs < 0)
			die(_("negative values not allowed for submodule.fetchJobs"));
		return 0;
	} else if (starts_with(var, "submodule."))
		return parse_submodule_config_option(var, value);
	else if (!strcmp(var, "fetch.recursesubmodules")) {
		config_fetch_recurse_submodules = parse_fetch_recurse_submodules_arg(var, value);
		return 0;
	}
	return 0;
}


int submodule_config(const char *var, const char *value, void *cb)
{
	if (!strcmp(var, "submodule.recurse")) {
		int v = git_config_bool(var, value) ? RECURSE_SUBMODULES_ON : RECURSE_SUBMODULES_OFF;
		config_update_recurse_submodules = v;
		return 0;
	} else {
		return git_modules_config(var, value, cb);
	}
}


int git_default_submodule_config(const char *var, const char *value, void *cb)
{
	if (!strcmp(var, "submodule.recurse")) {
		int v = git_config_bool(var, value) ? RECURSE_SUBMODULES_ON : RECURSE_SUBMODULES_OFF;
		config_update_recurse_submodules = v;
	}
	return 0;
}

int option_parse_recurse_submodules_worktree_updater(const struct option *opt, const char *arg, int unset)
{
	if (unset) {
		config_update_recurse_submodules = RECURSE_SUBMODULES_OFF;
		return 0;
	}
	if (arg)
		config_update_recurse_submodules = parse_update_recurse_submodules_arg(opt->long_name, arg);

	else config_update_recurse_submodules = RECURSE_SUBMODULES_ON;

	return 0;
}

void load_submodule_cache(void)
{
	if (config_update_recurse_submodules == RECURSE_SUBMODULES_OFF)
		return;

	gitmodules_config();
	git_config(submodule_config, NULL);
}

void gitmodules_config(void)
{
	const char *work_tree = get_git_work_tree();
	if (work_tree) {
		struct strbuf gitmodules_path = STRBUF_INIT;
		int pos;
		strbuf_addstr(&gitmodules_path, work_tree);
		strbuf_addstr(&gitmodules_path, "/.gitmodules");
		if (read_cache() < 0)
			die("index file corrupt");
		pos = cache_name_pos(".gitmodules", 11);
		if (pos < 0) { 
			pos = -1 - pos;
			if (active_nr > pos) {  
				const struct cache_entry *ce = active_cache[pos];
				if (ce_namelen(ce) == 11 && !memcmp(ce->name, ".gitmodules", 11))
					gitmodules_is_unmerged = 1;
			}
		} else if (pos < active_nr) {
			struct stat st;
			if (lstat(".gitmodules", &st) == 0 && ce_match_stat(active_cache[pos], &st, 0) & DATA_CHANGED)
				gitmodules_is_modified = 1;
		}

		if (!gitmodules_is_unmerged)
			git_config_from_file(git_modules_config, gitmodules_path.buf, NULL);
		strbuf_release(&gitmodules_path);
	}
}

static int gitmodules_cb(const char *var, const char *value, void *data)
{
	struct repository *repo = data;
	return submodule_config_option(repo, var, value);
}

void repo_read_gitmodules(struct repository *repo)
{
	char *gitmodules_path = repo_worktree_path(repo, ".gitmodules");

	git_config_from_file(gitmodules_cb, gitmodules_path, repo);
	free(gitmodules_path);
}

void gitmodules_config_sha1(const unsigned char *commit_sha1)
{
	struct strbuf rev = STRBUF_INIT;
	unsigned char sha1[20];

	if (gitmodule_sha1_from_commit(commit_sha1, sha1, &rev)) {
		git_config_from_blob_sha1(git_modules_config, rev.buf, sha1, NULL);
	}
	strbuf_release(&rev);
}


int is_submodule_active(struct repository *repo, const char *path)
{
	int ret = 0;
	char *key = NULL;
	char *value = NULL;
	const struct string_list *sl;
	const struct submodule *module;

	module = submodule_from_cache(repo, null_sha1, path);

	
	if (!module)
		return 0;

	
	key = xstrfmt("submodule.%s.active", module->name);
	if (!repo_config_get_bool(repo, key, &ret)) {
		free(key);
		return ret;
	}
	free(key);

	
	sl = repo_config_get_value_multi(repo, "submodule.active");
	if (sl) {
		struct pathspec ps;
		struct argv_array args = ARGV_ARRAY_INIT;
		const struct string_list_item *item;

		for_each_string_list_item(item, sl) {
			argv_array_push(&args, item->string);
		}

		parse_pathspec(&ps, 0, 0, NULL, args.argv);
		ret = match_pathspec(&ps, path, strlen(path), 0, NULL, 1);

		argv_array_clear(&args);
		clear_pathspec(&ps);
		return ret;
	}

	
	key = xstrfmt("submodule.%s.url", module->name);
	ret = !repo_config_get_string(repo, key, &value);

	free(value);
	free(key);
	return ret;
}

int is_submodule_populated_gently(const char *path, int *return_error_code)
{
	int ret = 0;
	char *gitdir = xstrfmt("%s/.git", path);

	if (resolve_gitdir_gently(gitdir, return_error_code))
		ret = 1;

	free(gitdir);
	return ret;
}


void die_in_unpopulated_submodule(const struct index_state *istate, const char *prefix)
{
	int i, prefixlen;

	if (!prefix)
		return;

	prefixlen = strlen(prefix);

	for (i = 0; i < istate->cache_nr; i++) {
		struct cache_entry *ce = istate->cache[i];
		int ce_len = ce_namelen(ce);

		if (!S_ISGITLINK(ce->ce_mode))
			continue;
		if (prefixlen <= ce_len)
			continue;
		if (strncmp(ce->name, prefix, ce_len))
			continue;
		if (prefix[ce_len] != '/')
			continue;

		die(_("in unpopulated submodule '%s'"), ce->name);
	}
}


void die_path_inside_submodule(const struct index_state *istate, const struct pathspec *ps)
{
	int i, j;

	for (i = 0; i < istate->cache_nr; i++) {
		struct cache_entry *ce = istate->cache[i];
		int ce_len = ce_namelen(ce);

		if (!S_ISGITLINK(ce->ce_mode))
			continue;

		for (j = 0; j < ps->nr ; j++) {
			const struct pathspec_item *item = &ps->items[j];

			if (item->len <= ce_len)
				continue;
			if (item->match[ce_len] != '/')
				continue;
			if (strncmp(ce->name, item->match, ce_len))
				continue;
			if (item->len == ce_len + 1)
				continue;

			die(_("Pathspec '%s' is in submodule '%.*s'"), item->original, ce_len, ce->name);
		}
	}
}

int parse_submodule_update_strategy(const char *value, struct submodule_update_strategy *dst)
{
	free((void*)dst->command);
	dst->command = NULL;
	if (!strcmp(value, "none"))
		dst->type = SM_UPDATE_NONE;
	else if (!strcmp(value, "checkout"))
		dst->type = SM_UPDATE_CHECKOUT;
	else if (!strcmp(value, "rebase"))
		dst->type = SM_UPDATE_REBASE;
	else if (!strcmp(value, "merge"))
		dst->type = SM_UPDATE_MERGE;
	else if (skip_prefix(value, "!", &value)) {
		dst->type = SM_UPDATE_COMMAND;
		dst->command = xstrdup(value);
	} else return -1;
	return 0;
}

const char *submodule_strategy_to_string(const struct submodule_update_strategy *s)
{
	struct strbuf sb = STRBUF_INIT;
	switch (s->type) {
	case SM_UPDATE_CHECKOUT:
		return "checkout";
	case SM_UPDATE_MERGE:
		return "merge";
	case SM_UPDATE_REBASE:
		return "rebase";
	case SM_UPDATE_NONE:
		return "none";
	case SM_UPDATE_UNSPECIFIED:
		return NULL;
	case SM_UPDATE_COMMAND:
		strbuf_addf(&sb, "!%s", s->command);
		return strbuf_detach(&sb, NULL);
	}
	return NULL;
}

void handle_ignore_submodules_arg(struct diff_options *diffopt, const char *arg)
{
	DIFF_OPT_CLR(diffopt, IGNORE_SUBMODULES);
	DIFF_OPT_CLR(diffopt, IGNORE_UNTRACKED_IN_SUBMODULES);
	DIFF_OPT_CLR(diffopt, IGNORE_DIRTY_SUBMODULES);

	if (!strcmp(arg, "all"))
		DIFF_OPT_SET(diffopt, IGNORE_SUBMODULES);
	else if (!strcmp(arg, "untracked"))
		DIFF_OPT_SET(diffopt, IGNORE_UNTRACKED_IN_SUBMODULES);
	else if (!strcmp(arg, "dirty"))
		DIFF_OPT_SET(diffopt, IGNORE_DIRTY_SUBMODULES);
	else if (strcmp(arg, "none"))
		die("bad --ignore-submodules argument: %s", arg);
}

static int prepare_submodule_summary(struct rev_info *rev, const char *path, struct commit *left, struct commit *right, struct commit_list *merge_bases)

{
	struct commit_list *list;

	init_revisions(rev, NULL);
	setup_revisions(0, NULL, rev, NULL);
	rev->left_right = 1;
	rev->first_parent_only = 1;
	left->object.flags |= SYMMETRIC_LEFT;
	add_pending_object(rev, &left->object, path);
	add_pending_object(rev, &right->object, path);
	for (list = merge_bases; list; list = list->next) {
		list->item->object.flags |= UNINTERESTING;
		add_pending_object(rev, &list->item->object, oid_to_hex(&list->item->object.oid));
	}
	return prepare_revision_walk(rev);
}

static void print_submodule_summary(struct rev_info *rev, FILE *f, const char *line_prefix, const char *del, const char *add, const char *reset)

{
	static const char format[] = "  %m %s";
	struct strbuf sb = STRBUF_INIT;
	struct commit *commit;

	while ((commit = get_revision(rev))) {
		struct pretty_print_context ctx = {0};
		ctx.date_mode = rev->date_mode;
		ctx.output_encoding = get_log_output_encoding();
		strbuf_setlen(&sb, 0);
		strbuf_addstr(&sb, line_prefix);
		if (commit->object.flags & SYMMETRIC_LEFT) {
			if (del)
				strbuf_addstr(&sb, del);
		}
		else if (add)
			strbuf_addstr(&sb, add);
		format_commit_message(commit, format, &sb, &ctx);
		if (reset)
			strbuf_addstr(&sb, reset);
		strbuf_addch(&sb, '\n');
		fprintf(f, "%s", sb.buf);
	}
	strbuf_release(&sb);
}

static void prepare_submodule_repo_env_no_git_dir(struct argv_array *out)
{
	const char * const *var;

	for (var = local_repo_env; *var; var++) {
		if (strcmp(*var, CONFIG_DATA_ENVIRONMENT))
			argv_array_push(out, *var);
	}
}

void prepare_submodule_repo_env(struct argv_array *out)
{
	prepare_submodule_repo_env_no_git_dir(out);
	argv_array_pushf(out, "%s=%s", GIT_DIR_ENVIRONMENT, DEFAULT_GIT_DIR_ENVIRONMENT);
}


static void show_submodule_header(FILE *f, const char *path, const char *line_prefix, struct object_id *one, struct object_id *two, unsigned dirty_submodule, const char *meta, const char *reset, struct commit **left, struct commit **right, struct commit_list **merge_bases)





{
	const char *message = NULL;
	struct strbuf sb = STRBUF_INIT;
	int fast_forward = 0, fast_backward = 0;

	if (dirty_submodule & DIRTY_SUBMODULE_UNTRACKED)
		fprintf(f, "%sSubmodule %s contains untracked content\n", line_prefix, path);
	if (dirty_submodule & DIRTY_SUBMODULE_MODIFIED)
		fprintf(f, "%sSubmodule %s contains modified content\n", line_prefix, path);

	if (is_null_oid(one))
		message = "(new submodule)";
	else if (is_null_oid(two))
		message = "(submodule deleted)";

	if (add_submodule_odb(path)) {
		if (!message)
			message = "(not initialized)";
		goto output_header;
	}

	
	*left = lookup_commit_reference(one);
	*right = lookup_commit_reference(two);

	
	if ((!is_null_oid(one) && !*left) || (!is_null_oid(two) && !*right))
		message = "(commits not present)";

	*merge_bases = get_merge_bases(*left, *right);
	if (*merge_bases) {
		if ((*merge_bases)->item == *left)
			fast_forward = 1;
		else if ((*merge_bases)->item == *right)
			fast_backward = 1;
	}

	if (!oidcmp(one, two)) {
		strbuf_release(&sb);
		return;
	}

output_header:
	strbuf_addf(&sb, "%s%sSubmodule %s ", line_prefix, meta, path);
	strbuf_add_unique_abbrev(&sb, one->hash, DEFAULT_ABBREV);
	strbuf_addstr(&sb, (fast_backward || fast_forward) ? ".." : "...");
	strbuf_add_unique_abbrev(&sb, two->hash, DEFAULT_ABBREV);
	if (message)
		strbuf_addf(&sb, " %s%s\n", message, reset);
	else strbuf_addf(&sb, "%s:%s\n", fast_backward ? " (rewind)" : "", reset);
	fwrite(sb.buf, sb.len, 1, f);

	strbuf_release(&sb);
}

void show_submodule_summary(FILE *f, const char *path, const char *line_prefix, struct object_id *one, struct object_id *two, unsigned dirty_submodule, const char *meta, const char *del, const char *add, const char *reset)



{
	struct rev_info rev;
	struct commit *left = NULL, *right = NULL;
	struct commit_list *merge_bases = NULL;

	show_submodule_header(f, path, line_prefix, one, two, dirty_submodule, meta, reset, &left, &right, &merge_bases);

	
	if (!left || !right)
		goto out;

	
	if (prepare_submodule_summary(&rev, path, left, right, merge_bases)) {
		fprintf(f, "%s(revision walker failed)\n", line_prefix);
		goto out;
	}

	print_submodule_summary(&rev, f, line_prefix, del, add, reset);

out:
	if (merge_bases)
		free_commit_list(merge_bases);
	clear_commit_marks(left, ~0);
	clear_commit_marks(right, ~0);
}

void show_submodule_inline_diff(FILE *f, const char *path, const char *line_prefix, struct object_id *one, struct object_id *two, unsigned dirty_submodule, const char *meta, const char *del, const char *add, const char *reset, const struct diff_options *o)




{
	const struct object_id *old = &empty_tree_oid, *new = &empty_tree_oid;
	struct commit *left = NULL, *right = NULL;
	struct commit_list *merge_bases = NULL;
	struct strbuf submodule_dir = STRBUF_INIT;
	struct child_process cp = CHILD_PROCESS_INIT;

	show_submodule_header(f, path, line_prefix, one, two, dirty_submodule, meta, reset, &left, &right, &merge_bases);

	
	if (!(left || is_null_oid(one)) || !(right || is_null_oid(two)))
		goto done;

	if (left)
		old = one;
	if (right)
		new = two;

	fflush(f);
	cp.git_cmd = 1;
	cp.dir = path;
	cp.out = dup(fileno(f));
	cp.no_stdin = 1;

	
	argv_array_pushl(&cp.args, "diff", "--submodule=diff", NULL);

	argv_array_pushf(&cp.args, "--line-prefix=%s", line_prefix);
	if (DIFF_OPT_TST(o, REVERSE_DIFF)) {
		argv_array_pushf(&cp.args, "--src-prefix=%s%s/", o->b_prefix, path);
		argv_array_pushf(&cp.args, "--dst-prefix=%s%s/", o->a_prefix, path);
	} else {
		argv_array_pushf(&cp.args, "--src-prefix=%s%s/", o->a_prefix, path);
		argv_array_pushf(&cp.args, "--dst-prefix=%s%s/", o->b_prefix, path);
	}
	argv_array_push(&cp.args, oid_to_hex(old));
	
	if (!(dirty_submodule & DIRTY_SUBMODULE_MODIFIED))
		argv_array_push(&cp.args, oid_to_hex(new));

	prepare_submodule_repo_env(&cp.env_array);
	if (run_command(&cp))
		fprintf(f, "(diff failed)\n");

done:
	strbuf_release(&submodule_dir);
	if (merge_bases)
		free_commit_list(merge_bases);
	if (left)
		clear_commit_marks(left, ~0);
	if (right)
		clear_commit_marks(right, ~0);
}

void set_config_fetch_recurse_submodules(int value)
{
	config_fetch_recurse_submodules = value;
}

int should_update_submodules(void)
{
	return config_update_recurse_submodules == RECURSE_SUBMODULES_ON;
}

const struct submodule *submodule_from_ce(const struct cache_entry *ce)
{
	if (!S_ISGITLINK(ce->ce_mode))
		return NULL;

	if (!should_update_submodules())
		return NULL;

	return submodule_from_path(null_sha1, ce->name);
}

static struct oid_array *submodule_commits(struct string_list *submodules, const char *path)
{
	struct string_list_item *item;

	item = string_list_insert(submodules, path);
	if (item->util)
		return (struct oid_array *) item->util;

	
	item->util = xcalloc(1, sizeof(struct oid_array));
	return (struct oid_array *) item->util;
}

static void collect_changed_submodules_cb(struct diff_queue_struct *q, struct diff_options *options, void *data)

{
	int i;
	struct string_list *changed = data;

	for (i = 0; i < q->nr; i++) {
		struct diff_filepair *p = q->queue[i];
		struct oid_array *commits;
		if (!S_ISGITLINK(p->two->mode))
			continue;

		if (S_ISGITLINK(p->one->mode)) {
			
			commits = submodule_commits(changed, p->two->path);
			oid_array_append(commits, &p->two->oid);
		} else {
			
			
			continue;
		}
	}
}


static void collect_changed_submodules(struct string_list *changed, struct argv_array *argv)
{
	struct rev_info rev;
	const struct commit *commit;

	init_revisions(&rev, NULL);
	setup_revisions(argv->argc, argv->argv, &rev, NULL);
	if (prepare_revision_walk(&rev))
		die("revision walk setup failed");

	while ((commit = get_revision(&rev))) {
		struct rev_info diff_rev;

		init_revisions(&diff_rev, NULL);
		diff_rev.diffopt.output_format |= DIFF_FORMAT_CALLBACK;
		diff_rev.diffopt.format_callback = collect_changed_submodules_cb;
		diff_rev.diffopt.format_callback_data = changed;
		diff_tree_combined_merge(commit, 1, &diff_rev);
	}

	reset_revision_walk();
}

static void free_submodules_oids(struct string_list *submodules)
{
	struct string_list_item *item;
	for_each_string_list_item(item, submodules)
		oid_array_clear((struct oid_array *) item->util);
	string_list_clear(submodules, 1);
}

static int has_remote(const char *refname, const struct object_id *oid, int flags, void *cb_data)
{
	return 1;
}

static int append_oid_to_argv(const struct object_id *oid, void *data)
{
	struct argv_array *argv = data;
	argv_array_push(argv, oid_to_hex(oid));
	return 0;
}

static int check_has_commit(const struct object_id *oid, void *data)
{
	int *has_commit = data;

	if (!lookup_commit_reference(oid))
		*has_commit = 0;

	return 0;
}

static int submodule_has_commits(const char *path, struct oid_array *commits)
{
	int has_commit = 1;

	
	if (add_submodule_odb(path))
		return 0;

	oid_array_for_each_unique(commits, check_has_commit, &has_commit);

	if (has_commit) {
		
		struct child_process cp = CHILD_PROCESS_INIT;
		struct strbuf out = STRBUF_INIT;

		argv_array_pushl(&cp.args, "rev-list", "-n", "1", NULL);
		oid_array_for_each_unique(commits, append_oid_to_argv, &cp.args);
		argv_array_pushl(&cp.args, "--not", "--all", NULL);

		prepare_submodule_repo_env(&cp.env_array);
		cp.git_cmd = 1;
		cp.no_stdin = 1;
		cp.dir = path;

		if (capture_command(&cp, &out, GIT_MAX_HEXSZ + 1) || out.len)
			has_commit = 0;

		strbuf_release(&out);
	}

	return has_commit;
}

static int submodule_needs_pushing(const char *path, struct oid_array *commits)
{
	if (!submodule_has_commits(path, commits))
		
		return 0;

	if (for_each_remote_ref_submodule(path, has_remote, NULL) > 0) {
		struct child_process cp = CHILD_PROCESS_INIT;
		struct strbuf buf = STRBUF_INIT;
		int needs_pushing = 0;

		argv_array_push(&cp.args, "rev-list");
		oid_array_for_each_unique(commits, append_oid_to_argv, &cp.args);
		argv_array_pushl(&cp.args, "--not", "--remotes", "-n", "1" , NULL);

		prepare_submodule_repo_env(&cp.env_array);
		cp.git_cmd = 1;
		cp.no_stdin = 1;
		cp.out = -1;
		cp.dir = path;
		if (start_command(&cp))
			die("Could not run 'git rev-list <commits> --not --remotes -n 1' command in submodule %s", path);
		if (strbuf_read(&buf, cp.out, 41))
			needs_pushing = 1;
		finish_command(&cp);
		close(cp.out);
		strbuf_release(&buf);
		return needs_pushing;
	}

	return 0;
}

int find_unpushed_submodules(struct oid_array *commits, const char *remotes_name, struct string_list *needs_pushing)
{
	struct string_list submodules = STRING_LIST_INIT_DUP;
	struct string_list_item *submodule;
	struct argv_array argv = ARGV_ARRAY_INIT;

	
	argv_array_push(&argv, "find_unpushed_submodules");
	oid_array_for_each_unique(commits, append_oid_to_argv, &argv);
	argv_array_push(&argv, "--not");
	argv_array_pushf(&argv, "--remotes=%s", remotes_name);

	collect_changed_submodules(&submodules, &argv);

	for_each_string_list_item(submodule, &submodules) {
		struct oid_array *commits = submodule->util;
		const char *path = submodule->string;

		if (submodule_needs_pushing(path, commits))
			string_list_insert(needs_pushing, path);
	}

	free_submodules_oids(&submodules);
	argv_array_clear(&argv);

	return needs_pushing->nr;
}

static int push_submodule(const char *path, const struct remote *remote, const char **refspec, int refspec_nr, const struct string_list *push_options, int dry_run)



{
	if (add_submodule_odb(path))
		return 1;

	if (for_each_remote_ref_submodule(path, has_remote, NULL) > 0) {
		struct child_process cp = CHILD_PROCESS_INIT;
		argv_array_push(&cp.args, "push");
		if (dry_run)
			argv_array_push(&cp.args, "--dry-run");

		if (push_options && push_options->nr) {
			const struct string_list_item *item;
			for_each_string_list_item(item, push_options)
				argv_array_pushf(&cp.args, "--push-option=%s", item->string);
		}

		if (remote->origin != REMOTE_UNCONFIGURED) {
			int i;
			argv_array_push(&cp.args, remote->name);
			for (i = 0; i < refspec_nr; i++)
				argv_array_push(&cp.args, refspec[i]);
		}

		prepare_submodule_repo_env(&cp.env_array);
		cp.git_cmd = 1;
		cp.no_stdin = 1;
		cp.dir = path;
		if (run_command(&cp))
			return 0;
		close(cp.out);
	}

	return 1;
}


static void submodule_push_check(const char *path, const char *head, const struct remote *remote, const char **refspec, int refspec_nr)

{
	struct child_process cp = CHILD_PROCESS_INIT;
	int i;

	argv_array_push(&cp.args, "submodule--helper");
	argv_array_push(&cp.args, "push-check");
	argv_array_push(&cp.args, head);
	argv_array_push(&cp.args, remote->name);

	for (i = 0; i < refspec_nr; i++)
		argv_array_push(&cp.args, refspec[i]);

	prepare_submodule_repo_env(&cp.env_array);
	cp.git_cmd = 1;
	cp.no_stdin = 1;
	cp.no_stdout = 1;
	cp.dir = path;

	
	if (run_command(&cp))
		die("process for submodule '%s' failed", path);
}

int push_unpushed_submodules(struct oid_array *commits, const struct remote *remote, const char **refspec, int refspec_nr, const struct string_list *push_options, int dry_run)



{
	int i, ret = 1;
	struct string_list needs_pushing = STRING_LIST_INIT_DUP;

	if (!find_unpushed_submodules(commits, remote->name, &needs_pushing))
		return 1;

	
	if (remote->origin != REMOTE_UNCONFIGURED) {
		char *head;
		struct object_id head_oid;

		head = resolve_refdup("HEAD", 0, head_oid.hash, NULL);
		if (!head)
			die(_("Failed to resolve HEAD as a valid ref."));

		for (i = 0; i < needs_pushing.nr; i++)
			submodule_push_check(needs_pushing.items[i].string, head, remote, refspec, refspec_nr);

		free(head);
	}

	
	for (i = 0; i < needs_pushing.nr; i++) {
		const char *path = needs_pushing.items[i].string;
		fprintf(stderr, "Pushing submodule '%s'\n", path);
		if (!push_submodule(path, remote, refspec, refspec_nr, push_options, dry_run)) {
			fprintf(stderr, "Unable to push submodule '%s'\n", path);
			ret = 0;
		}
	}

	string_list_clear(&needs_pushing, 0);

	return ret;
}

static int append_oid_to_array(const char *ref, const struct object_id *oid, int flags, void *data)
{
	struct oid_array *array = data;
	oid_array_append(array, oid);
	return 0;
}

void check_for_new_submodule_commits(struct object_id *oid)
{
	if (!initialized_fetch_ref_tips) {
		for_each_ref(append_oid_to_array, &ref_tips_before_fetch);
		initialized_fetch_ref_tips = 1;
	}

	oid_array_append(&ref_tips_after_fetch, oid);
}

static void calculate_changed_submodule_paths(void)
{
	struct argv_array argv = ARGV_ARRAY_INIT;
	struct string_list changed_submodules = STRING_LIST_INIT_DUP;
	const struct string_list_item *item;

	
	if (!submodule_from_path(NULL, NULL))
		return;

	argv_array_push(&argv, "--"); 
	oid_array_for_each_unique(&ref_tips_after_fetch, append_oid_to_argv, &argv);
	argv_array_push(&argv, "--not");
	oid_array_for_each_unique(&ref_tips_before_fetch, append_oid_to_argv, &argv);

	
	collect_changed_submodules(&changed_submodules, &argv);

	for_each_string_list_item(item, &changed_submodules) {
		struct oid_array *commits = item->util;
		const char *path = item->string;

		if (!submodule_has_commits(path, commits))
			string_list_append(&changed_submodule_paths, path);
	}

	free_submodules_oids(&changed_submodules);
	argv_array_clear(&argv);
	oid_array_clear(&ref_tips_before_fetch);
	oid_array_clear(&ref_tips_after_fetch);
	initialized_fetch_ref_tips = 0;
}

int submodule_touches_in_range(struct object_id *excl_oid, struct object_id *incl_oid)
{
	struct string_list subs = STRING_LIST_INIT_DUP;
	struct argv_array args = ARGV_ARRAY_INIT;
	int ret;

	gitmodules_config();
	
	if (!submodule_from_path(NULL, NULL))
		return 0;

	argv_array_push(&args, "--"); 
	argv_array_push(&args, oid_to_hex(incl_oid));
	argv_array_push(&args, "--not");
	argv_array_push(&args, oid_to_hex(excl_oid));

	collect_changed_submodules(&subs, &args);
	ret = subs.nr;

	argv_array_clear(&args);

	free_submodules_oids(&subs);
	return ret;
}

struct submodule_parallel_fetch {
	int count;
	struct argv_array args;
	const char *work_tree;
	const char *prefix;
	int command_line_option;
	int quiet;
	int result;
};


static int get_next_submodule(struct child_process *cp, struct strbuf *err, void *data, void **task_cb)
{
	int ret = 0;
	struct submodule_parallel_fetch *spf = data;

	for (; spf->count < active_nr; spf->count++) {
		struct strbuf submodule_path = STRBUF_INIT;
		struct strbuf submodule_git_dir = STRBUF_INIT;
		struct strbuf submodule_prefix = STRBUF_INIT;
		const struct cache_entry *ce = active_cache[spf->count];
		const char *git_dir, *default_argv;
		const struct submodule *submodule;

		if (!S_ISGITLINK(ce->ce_mode))
			continue;

		submodule = submodule_from_path(null_sha1, ce->name);
		if (!submodule)
			submodule = submodule_from_name(null_sha1, ce->name);

		default_argv = "yes";
		if (spf->command_line_option == RECURSE_SUBMODULES_DEFAULT) {
			if (submodule && submodule->fetch_recurse != RECURSE_SUBMODULES_NONE) {

				if (submodule->fetch_recurse == RECURSE_SUBMODULES_OFF)
					continue;
				if (submodule->fetch_recurse == RECURSE_SUBMODULES_ON_DEMAND) {
					if (!unsorted_string_list_lookup(&changed_submodule_paths, ce->name))
						continue;
					default_argv = "on-demand";
				}
			} else {
				if ((config_fetch_recurse_submodules == RECURSE_SUBMODULES_OFF) || gitmodules_is_unmerged)
					continue;
				if (config_fetch_recurse_submodules == RECURSE_SUBMODULES_ON_DEMAND) {
					if (!unsorted_string_list_lookup(&changed_submodule_paths, ce->name))
						continue;
					default_argv = "on-demand";
				}
			}
		} else if (spf->command_line_option == RECURSE_SUBMODULES_ON_DEMAND) {
			if (!unsorted_string_list_lookup(&changed_submodule_paths, ce->name))
				continue;
			default_argv = "on-demand";
		}

		strbuf_addf(&submodule_path, "%s/%s", spf->work_tree, ce->name);
		strbuf_addf(&submodule_git_dir, "%s/.git", submodule_path.buf);
		strbuf_addf(&submodule_prefix, "%s%s/", spf->prefix, ce->name);
		git_dir = read_gitfile(submodule_git_dir.buf);
		if (!git_dir)
			git_dir = submodule_git_dir.buf;
		if (is_directory(git_dir)) {
			child_process_init(cp);
			cp->dir = strbuf_detach(&submodule_path, NULL);
			prepare_submodule_repo_env(&cp->env_array);
			cp->git_cmd = 1;
			if (!spf->quiet)
				strbuf_addf(err, "Fetching submodule %s%s\n", spf->prefix, ce->name);
			argv_array_init(&cp->args);
			argv_array_pushv(&cp->args, spf->args.argv);
			argv_array_push(&cp->args, default_argv);
			argv_array_push(&cp->args, "--submodule-prefix");
			argv_array_push(&cp->args, submodule_prefix.buf);
			ret = 1;
		}
		strbuf_release(&submodule_path);
		strbuf_release(&submodule_git_dir);
		strbuf_release(&submodule_prefix);
		if (ret) {
			spf->count++;
			return 1;
		}
	}
	return 0;
}

static int fetch_start_failure(struct strbuf *err, void *cb, void *task_cb)
{
	struct submodule_parallel_fetch *spf = cb;

	spf->result = 1;

	return 0;
}

static int fetch_finish(int retvalue, struct strbuf *err, void *cb, void *task_cb)
{
	struct submodule_parallel_fetch *spf = cb;

	if (retvalue)
		spf->result = 1;

	return 0;
}

int fetch_populated_submodules(const struct argv_array *options, const char *prefix, int command_line_option, int quiet, int max_parallel_jobs)

{
	int i;
	struct submodule_parallel_fetch spf = SPF_INIT;

	spf.work_tree = get_git_work_tree();
	spf.command_line_option = command_line_option;
	spf.quiet = quiet;
	spf.prefix = prefix;

	if (!spf.work_tree)
		goto out;

	if (read_cache() < 0)
		die("index file corrupt");

	argv_array_push(&spf.args, "fetch");
	for (i = 0; i < options->argc; i++)
		argv_array_push(&spf.args, options->argv[i]);
	argv_array_push(&spf.args, "--recurse-submodules-default");
	

	if (max_parallel_jobs < 0)
		max_parallel_jobs = parallel_jobs;

	calculate_changed_submodule_paths();
	run_processes_parallel(max_parallel_jobs, get_next_submodule, fetch_start_failure, fetch_finish, &spf);




	argv_array_clear(&spf.args);
out:
	string_list_clear(&changed_submodule_paths, 1);
	return spf.result;
}

unsigned is_submodule_modified(const char *path, int ignore_untracked)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf buf = STRBUF_INIT;
	FILE *fp;
	unsigned dirty_submodule = 0;
	const char *git_dir;
	int ignore_cp_exit_code = 0;

	strbuf_addf(&buf, "%s/.git", path);
	git_dir = read_gitfile(buf.buf);
	if (!git_dir)
		git_dir = buf.buf;
	if (!is_git_directory(git_dir)) {
		if (is_directory(git_dir))
			die(_("'%s' not recognized as a git repository"), git_dir);
		strbuf_release(&buf);
		
		return 0;
	}
	strbuf_reset(&buf);

	argv_array_pushl(&cp.args, "status", "--porcelain=2", NULL);
	if (ignore_untracked)
		argv_array_push(&cp.args, "-uno");

	prepare_submodule_repo_env(&cp.env_array);
	cp.git_cmd = 1;
	cp.no_stdin = 1;
	cp.out = -1;
	cp.dir = path;
	if (start_command(&cp))
		die("Could not run 'git status --porcelain=2' in submodule %s", path);

	fp = xfdopen(cp.out, "r");
	while (strbuf_getwholeline(&buf, fp, '\n') != EOF) {
		
		if (buf.buf[0] == '?')
			dirty_submodule |= DIRTY_SUBMODULE_UNTRACKED;

		if (buf.buf[0] == 'u' || buf.buf[0] == '1' || buf.buf[0] == '2') {

			
			if (buf.len < strlen("T XY SSSS"))
				die("BUG: invalid status --porcelain=2 line %s", buf.buf);

			if (buf.buf[5] == 'S' && buf.buf[8] == 'U')
				
				dirty_submodule |= DIRTY_SUBMODULE_UNTRACKED;

			if (buf.buf[0] == 'u' || buf.buf[0] == '2' || memcmp(buf.buf + 5, "S..U", 4))

				
				dirty_submodule |= DIRTY_SUBMODULE_MODIFIED;
		}

		if ((dirty_submodule & DIRTY_SUBMODULE_MODIFIED) && ((dirty_submodule & DIRTY_SUBMODULE_UNTRACKED) || ignore_untracked)) {

			
			ignore_cp_exit_code = 1;
			break;
		}
	}
	fclose(fp);

	if (finish_command(&cp) && !ignore_cp_exit_code)
		die("'git status --porcelain=2' failed in submodule %s", path);

	strbuf_release(&buf);
	return dirty_submodule;
}

int submodule_uses_gitfile(const char *path)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	const char *argv[] = {
		"submodule", "foreach", "--quiet", "--recursive", "test -f .git", NULL, };





	struct strbuf buf = STRBUF_INIT;
	const char *git_dir;

	strbuf_addf(&buf, "%s/.git", path);
	git_dir = read_gitfile(buf.buf);
	if (!git_dir) {
		strbuf_release(&buf);
		return 0;
	}
	strbuf_release(&buf);

	
	cp.argv = argv;
	prepare_submodule_repo_env(&cp.env_array);
	cp.git_cmd = 1;
	cp.no_stdin = 1;
	cp.no_stderr = 1;
	cp.no_stdout = 1;
	cp.dir = path;
	if (run_command(&cp))
		return 0;

	return 1;
}


int bad_to_remove_submodule(const char *path, unsigned flags)
{
	ssize_t len;
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf buf = STRBUF_INIT;
	int ret = 0;

	if (!file_exists(path) || is_empty_dir(path))
		return 0;

	if (!submodule_uses_gitfile(path))
		return 1;

	argv_array_pushl(&cp.args, "status", "--porcelain", "--ignore-submodules=none", NULL);

	if (flags & SUBMODULE_REMOVAL_IGNORE_UNTRACKED)
		argv_array_push(&cp.args, "-uno");
	else argv_array_push(&cp.args, "-uall");

	if (!(flags & SUBMODULE_REMOVAL_IGNORE_IGNORED_UNTRACKED))
		argv_array_push(&cp.args, "--ignored");

	prepare_submodule_repo_env(&cp.env_array);
	cp.git_cmd = 1;
	cp.no_stdin = 1;
	cp.out = -1;
	cp.dir = path;
	if (start_command(&cp)) {
		if (flags & SUBMODULE_REMOVAL_DIE_ON_ERROR)
			die(_("could not start 'git status' in submodule '%s'"), path);
		ret = -1;
		goto out;
	}

	len = strbuf_read(&buf, cp.out, 1024);
	if (len > 2)
		ret = 1;
	close(cp.out);

	if (finish_command(&cp)) {
		if (flags & SUBMODULE_REMOVAL_DIE_ON_ERROR)
			die(_("could not run 'git status' in submodule '%s'"), path);
		ret = -1;
	}
out:
	strbuf_release(&buf);
	return ret;
}

static const char *get_super_prefix_or_empty(void)
{
	const char *s = get_super_prefix();
	if (!s)
		s = "";
	return s;
}

static int submodule_has_dirty_index(const struct submodule *sub)
{
	struct child_process cp = CHILD_PROCESS_INIT;

	prepare_submodule_repo_env(&cp.env_array);

	cp.git_cmd = 1;
	argv_array_pushl(&cp.args, "diff-index", "--quiet", "--cached", "HEAD", NULL);
	cp.no_stdin = 1;
	cp.no_stdout = 1;
	cp.dir = sub->path;
	if (start_command(&cp))
		die("could not recurse into submodule '%s'", sub->path);

	return finish_command(&cp);
}

static void submodule_reset_index(const char *path)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	prepare_submodule_repo_env(&cp.env_array);

	cp.git_cmd = 1;
	cp.no_stdin = 1;
	cp.dir = path;

	argv_array_pushf(&cp.args, "--super-prefix=%s%s/", get_super_prefix_or_empty(), path);
	argv_array_pushl(&cp.args, "read-tree", "-u", "--reset", NULL);

	argv_array_push(&cp.args, EMPTY_TREE_SHA1_HEX);

	if (run_command(&cp))
		die("could not reset submodule index");
}


int submodule_move_head(const char *path, const char *old, const char *new, unsigned flags)


{
	int ret = 0;
	struct child_process cp = CHILD_PROCESS_INIT;
	const struct submodule *sub;
	int *error_code_ptr, error_code;

	if (!is_submodule_active(the_repository, path))
		return 0;

	if (flags & SUBMODULE_MOVE_HEAD_FORCE)
		
		error_code_ptr = &error_code;
	else error_code_ptr = NULL;

	if (old && !is_submodule_populated_gently(path, error_code_ptr))
		return 0;

	sub = submodule_from_path(null_sha1, path);

	if (!sub)
		die("BUG: could not get submodule information for '%s'", path);

	if (old && !(flags & SUBMODULE_MOVE_HEAD_FORCE)) {
		
		if (submodule_has_dirty_index(sub))
			return error(_("submodule '%s' has dirty index"), path);
	}

	if (!(flags & SUBMODULE_MOVE_HEAD_DRY_RUN)) {
		if (old) {
			if (!submodule_uses_gitfile(path))
				absorb_git_dir_into_superproject("", path, ABSORB_GITDIR_RECURSE_SUBMODULES);
		} else {
			char *gitdir = xstrfmt("%s/modules/%s", get_git_common_dir(), sub->name);
			connect_work_tree_and_git_dir(path, gitdir);
			free(gitdir);

			
			submodule_reset_index(path);
		}

		if (old && (flags & SUBMODULE_MOVE_HEAD_FORCE)) {
			char *gitdir = xstrfmt("%s/modules/%s", get_git_common_dir(), sub->name);
			connect_work_tree_and_git_dir(path, gitdir);
			free(gitdir);
		}
	}

	prepare_submodule_repo_env(&cp.env_array);

	cp.git_cmd = 1;
	cp.no_stdin = 1;
	cp.dir = path;

	argv_array_pushf(&cp.args, "--super-prefix=%s%s/", get_super_prefix_or_empty(), path);
	argv_array_pushl(&cp.args, "read-tree", "--recurse-submodules", NULL);

	if (flags & SUBMODULE_MOVE_HEAD_DRY_RUN)
		argv_array_push(&cp.args, "-n");
	else argv_array_push(&cp.args, "-u");

	if (flags & SUBMODULE_MOVE_HEAD_FORCE)
		argv_array_push(&cp.args, "--reset");
	else argv_array_push(&cp.args, "-m");

	argv_array_push(&cp.args, old ? old : EMPTY_TREE_SHA1_HEX);
	argv_array_push(&cp.args, new ? new : EMPTY_TREE_SHA1_HEX);

	if (run_command(&cp)) {
		ret = -1;
		goto out;
	}

	if (!(flags & SUBMODULE_MOVE_HEAD_DRY_RUN)) {
		if (new) {
			child_process_init(&cp);
			
			cp.git_cmd = 1;
			cp.no_stdin = 1;
			cp.dir = path;

			prepare_submodule_repo_env(&cp.env_array);
			argv_array_pushl(&cp.args, "update-ref", "HEAD", new, NULL);

			if (run_command(&cp)) {
				ret = -1;
				goto out;
			}
		} else {
			struct strbuf sb = STRBUF_INIT;

			strbuf_addf(&sb, "%s/.git", path);
			unlink_or_warn(sb.buf);
			strbuf_release(&sb);

			if (is_empty_dir(path))
				rmdir_or_warn(path);
		}
	}
out:
	return ret;
}

static int find_first_merges(struct object_array *result, const char *path, struct commit *a, struct commit *b)
{
	int i, j;
	struct object_array merges = OBJECT_ARRAY_INIT;
	struct commit *commit;
	int contains_another;

	char merged_revision[42];
	const char *rev_args[] = { "rev-list", "--merges", "--ancestry-path", "--all", merged_revision, NULL };
	struct rev_info revs;
	struct setup_revision_opt rev_opts;

	memset(result, 0, sizeof(struct object_array));
	memset(&rev_opts, 0, sizeof(rev_opts));

	
	xsnprintf(merged_revision, sizeof(merged_revision), "^%s", oid_to_hex(&a->object.oid));
	init_revisions(&revs, NULL);
	rev_opts.submodule = path;
	setup_revisions(ARRAY_SIZE(rev_args)-1, rev_args, &revs, &rev_opts);

	
	if (prepare_revision_walk(&revs))
		die("revision walk setup failed");
	while ((commit = get_revision(&revs)) != NULL) {
		struct object *o = &(commit->object);
		if (in_merge_bases(b, commit))
			add_object_array(o, NULL, &merges);
	}
	reset_revision_walk();

	
	for (i = 0; i < merges.nr; i++) {
		struct commit *m1 = (struct commit *) merges.objects[i].item;

		contains_another = 0;
		for (j = 0; j < merges.nr; j++) {
			struct commit *m2 = (struct commit *) merges.objects[j].item;
			if (i != j && in_merge_bases(m2, m1)) {
				contains_another = 1;
				break;
			}
		}

		if (!contains_another)
			add_object_array(merges.objects[i].item, NULL, result);
	}

	free(merges.objects);
	return result->nr;
}

static void print_commit(struct commit *commit)
{
	struct strbuf sb = STRBUF_INIT;
	struct pretty_print_context ctx = {0};
	ctx.date_mode.type = DATE_NORMAL;
	format_commit_message(commit, " %h: %m %s", &sb, &ctx);
	fprintf(stderr, "%s\n", sb.buf);
	strbuf_release(&sb);
}



int merge_submodule(struct object_id *result, const char *path, const struct object_id *base, const struct object_id *a, const struct object_id *b, int search)

{
	struct commit *commit_base, *commit_a, *commit_b;
	int parent_count;
	struct object_array merges;

	int i;

	
	oidcpy(result, a);

	
	if (is_null_oid(base))
		return 0;
	if (is_null_oid(a))
		return 0;
	if (is_null_oid(b))
		return 0;

	if (add_submodule_odb(path)) {
		MERGE_WARNING(path, "not checked out");
		return 0;
	}

	if (!(commit_base = lookup_commit_reference(base)) || !(commit_a = lookup_commit_reference(a)) || !(commit_b = lookup_commit_reference(b))) {

		MERGE_WARNING(path, "commits not present");
		return 0;
	}

	
	if (!in_merge_bases(commit_base, commit_a) || !in_merge_bases(commit_base, commit_b)) {
		MERGE_WARNING(path, "commits don't follow merge-base");
		return 0;
	}

	
	if (in_merge_bases(commit_a, commit_b)) {
		oidcpy(result, b);
		return 1;
	}
	if (in_merge_bases(commit_b, commit_a)) {
		oidcpy(result, a);
		return 1;
	}

	

	
	if (!search)
		return 0;

	
	parent_count = find_first_merges(&merges, path, commit_a, commit_b);
	switch (parent_count) {
	case 0:
		MERGE_WARNING(path, "merge following commits not found");
		break;

	case 1:
		MERGE_WARNING(path, "not fast-forward");
		fprintf(stderr, "Found a possible merge resolution " "for the submodule:\n");
		print_commit((struct commit *) merges.objects[0].item);
		fprintf(stderr, "If this is correct simply add it to the index " "for example\n" "by using:\n\n" "  git update-index --cacheinfo 160000 %s \"%s\"\n\n" "which will accept this suggestion.\n", oid_to_hex(&merges.objects[0].item->oid), path);





		break;

	default:
		MERGE_WARNING(path, "multiple merges found");
		for (i = 0; i < merges.nr; i++)
			print_commit((struct commit *) merges.objects[i].item);
	}

	free(merges.objects);
	return 0;
}

int parallel_submodules(void)
{
	return parallel_jobs;
}


static void relocate_single_git_dir_into_superproject(const char *prefix, const char *path)
{
	char *old_git_dir = NULL, *real_old_git_dir = NULL, *real_new_git_dir = NULL;
	const char *new_git_dir;
	const struct submodule *sub;

	if (submodule_uses_worktrees(path))
		die(_("relocate_gitdir for submodule '%s' with " "more than one worktree not supported"), path);

	old_git_dir = xstrfmt("%s/.git", path);
	if (read_gitfile(old_git_dir))
		
		return;

	real_old_git_dir = real_pathdup(old_git_dir, 1);

	sub = submodule_from_path(null_sha1, path);
	if (!sub)
		die(_("could not lookup name for submodule '%s'"), path);

	new_git_dir = git_path("modules/%s", sub->name);
	if (safe_create_leading_directories_const(new_git_dir) < 0)
		die(_("could not create directory '%s'"), new_git_dir);
	real_new_git_dir = real_pathdup(new_git_dir, 1);

	fprintf(stderr, _("Migrating git directory of '%s%s' from\n'%s' to\n'%s'\n"), get_super_prefix_or_empty(), path, real_old_git_dir, real_new_git_dir);


	relocate_gitdir(path, real_old_git_dir, real_new_git_dir);

	free(old_git_dir);
	free(real_old_git_dir);
	free(real_new_git_dir);
}


void absorb_git_dir_into_superproject(const char *prefix, const char *path, unsigned flags)

{
	int err_code;
	const char *sub_git_dir;
	struct strbuf gitdir = STRBUF_INIT;
	strbuf_addf(&gitdir, "%s/.git", path);
	sub_git_dir = resolve_gitdir_gently(gitdir.buf, &err_code);

	
	if (!sub_git_dir) {
		const struct submodule *sub;

		if (err_code == READ_GITFILE_ERR_STAT_FAILED) {
			
			strbuf_release(&gitdir);
			return;
		}

		if (err_code != READ_GITFILE_ERR_NOT_A_REPO)
			
			read_gitfile_error_die(err_code, path, NULL);

		
		sub = submodule_from_path(null_sha1, path);
		if (!sub)
			die(_("could not lookup name for submodule '%s'"), path);
		connect_work_tree_and_git_dir(path, git_path("modules/%s", sub->name));
	} else {
		
		char *real_sub_git_dir = real_pathdup(sub_git_dir, 1);
		char *real_common_git_dir = real_pathdup(get_git_common_dir(), 1);

		if (!starts_with(real_sub_git_dir, real_common_git_dir))
			relocate_single_git_dir_into_superproject(prefix, path);

		free(real_sub_git_dir);
		free(real_common_git_dir);
	}
	strbuf_release(&gitdir);

	if (flags & ABSORB_GITDIR_RECURSE_SUBMODULES) {
		struct child_process cp = CHILD_PROCESS_INIT;
		struct strbuf sb = STRBUF_INIT;

		if (flags & ~ABSORB_GITDIR_RECURSE_SUBMODULES)
			die("BUG: we don't know how to pass the flags down?");

		strbuf_addstr(&sb, get_super_prefix_or_empty());
		strbuf_addstr(&sb, path);
		strbuf_addch(&sb, '/');

		cp.dir = path;
		cp.git_cmd = 1;
		cp.no_stdin = 1;
		argv_array_pushl(&cp.args, "--super-prefix", sb.buf, "submodule--helper", "absorb-git-dirs", NULL);

		prepare_submodule_repo_env(&cp.env_array);
		if (run_command(&cp))
			die(_("could not recurse into submodule '%s'"), path);

		strbuf_release(&sb);
	}
}

const char *get_superproject_working_tree(void)
{
	struct child_process cp = CHILD_PROCESS_INIT;
	struct strbuf sb = STRBUF_INIT;
	const char *one_up = real_path_if_valid("../");
	const char *cwd = xgetcwd();
	const char *ret = NULL;
	const char *subpath;
	int code;
	ssize_t len;

	if (!is_inside_work_tree())
		
		return NULL;

	if (!one_up)
		return NULL;

	subpath = relative_path(cwd, one_up, &sb);

	prepare_submodule_repo_env(&cp.env_array);
	argv_array_pop(&cp.env_array);

	argv_array_pushl(&cp.args, "--literal-pathspecs", "-C", "..", "ls-files", "-z", "--stage", "--full-name", "--", subpath, NULL);

	strbuf_reset(&sb);

	cp.no_stdin = 1;
	cp.no_stderr = 1;
	cp.out = -1;
	cp.git_cmd = 1;

	if (start_command(&cp))
		die(_("could not start ls-files in .."));

	len = strbuf_read(&sb, cp.out, PATH_MAX);
	close(cp.out);

	if (starts_with(sb.buf, "160000")) {
		int super_sub_len;
		int cwd_len = strlen(cwd);
		char *super_sub, *super_wt;

		
		super_sub = strchr(sb.buf, '\t') + 1;
		super_sub_len = sb.buf + sb.len - super_sub - 1;

		if (super_sub_len > cwd_len || strcmp(&cwd[cwd_len - super_sub_len], super_sub))
			die (_("BUG: returned path string doesn't match cwd?"));

		super_wt = xstrdup(cwd);
		super_wt[cwd_len - super_sub_len] = '\0';

		ret = real_path(super_wt);
		free(super_wt);
	}
	strbuf_release(&sb);

	code = finish_command(&cp);

	if (code == 128)
		
		return NULL;
	if (code == 0 && len == 0)
		
		return NULL;
	if (code)
		die(_("ls-tree returned unexpected return code %d"), code);

	return ret;
}

int submodule_to_gitdir(struct strbuf *buf, const char *submodule)
{
	const struct submodule *sub;
	const char *git_dir;
	int ret = 0;

	strbuf_reset(buf);
	strbuf_addstr(buf, submodule);
	strbuf_complete(buf, '/');
	strbuf_addstr(buf, ".git");

	git_dir = read_gitfile(buf->buf);
	if (git_dir) {
		strbuf_reset(buf);
		strbuf_addstr(buf, git_dir);
	}
	if (!is_git_directory(buf->buf)) {
		gitmodules_config();
		sub = submodule_from_path(null_sha1, submodule);
		if (!sub) {
			ret = -1;
			goto cleanup;
		}
		strbuf_reset(buf);
		strbuf_git_path(buf, "%s/%s", "modules", sub->name);
	}

cleanup:
	return ret;
}
